#include "httplib.h"
#include "nlohmann/json.hpp"
#include <sqlite3.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <fstream>
#include <sstream>
#include <mutex>
#include <memory>
#include <map>
#include <set>
#include <functional>
#include <filesystem>
#include <thread>
#include <cstring>
#include <ctime>
#include <openssl/hmac.h>
#include <curl/curl.h>
using namespace std; using json=nlohmann::json; using namespace httplib;
struct HttpErr{int code;string msg;};
// ---- security helpers ----
string hex(const unsigned char*d,size_t n){static const char*h="0123456789abcdef";string s;for(size_t i=0;i<n;i++){s+=h[d[i]>>4];s+=h[d[i]&15];}return s;}
string rnd(int n){vector<unsigned char>b(n);RAND_bytes(b.data(),n);return hex(b.data(),n);}
string hashPw(const string&pw,const string&salt){unsigned char o[32];PKCS5_PBKDF2_HMAC(pw.c_str(),pw.size(),(const unsigned char*)salt.data(),salt.size(),100000,EVP_sha256(),32,o);return salt+"$"+hex(o,32);}
bool checkPw(const string&pw,const string&st){return hashPw(pw,st.substr(0,st.find('$')))==st;}
// ---- RAII database wrapper (parameterized queries only) ----
class Db{sqlite3*d=nullptr;public:
 explicit Db(const string&p){if(sqlite3_open(p.c_str(),&d))throw runtime_error("cannot open db");}
 ~Db(){sqlite3_close(d);} Db(const Db&)=delete; Db&operator=(const Db&)=delete;
 void exec(const string&sql){char*e=nullptr;if(sqlite3_exec(d,sql.c_str(),0,0,&e)){string m=e;sqlite3_free(e);throw runtime_error(m);}}
 json q(const string&sql,const vector<string>&p={}){sqlite3_stmt*s;if(sqlite3_prepare_v2(d,sql.c_str(),-1,&s,0))throw runtime_error(sqlite3_errmsg(d));
  for(size_t i=0;i<p.size();i++)sqlite3_bind_text(s,i+1,p[i].c_str(),-1,SQLITE_TRANSIENT);
  json r=json::array();int rc;
  while((rc=sqlite3_step(s))==SQLITE_ROW){json o;for(int c=0;c<sqlite3_column_count(s);c++){string n=sqlite3_column_name(s,c);int t=sqlite3_column_type(s,c);
   if(t==SQLITE_INTEGER)o[n]=sqlite3_column_int64(s,c);else if(t==SQLITE_NULL)o[n]=nullptr;else o[n]=string((const char*)sqlite3_column_text(s,c));}r.push_back(o);}
  sqlite3_finalize(s);if(rc!=SQLITE_DONE)throw runtime_error(sqlite3_errmsg(d));return r;}
 long long lastId(){return sqlite3_last_insert_rowid(d);}
};
// ---- User hierarchy: runtime polymorphism for permissions ----
struct User{long long id;string name,email,role;virtual ~User()=default;
 virtual bool canReview()const{return false;} virtual bool canManageEvents()const{return false;} virtual bool canRegister()const{return false;}};
struct Student:User{bool canRegister()const override{return true;}};
struct Organizer:User{bool canManageEvents()const override{return true;}};
struct Admin:User{bool canReview()const override{return true;} bool canManageEvents()const override{return true;}};
unique_ptr<User> makeUser(const json&j){unique_ptr<User>u;string r=j["role"];
 if(r=="admin")u=make_unique<Admin>();else if(r=="organizer")u=make_unique<Organizer>();else u=make_unique<Student>();
 u->id=j["id"];u->name=j["name"];u->email=j["email"];u->role=r;return u;}

string genv(const char*k,const char*d=""){const char*v=getenv(k);return string(v?v:d);}
string b64(const string&s){string o(4*((s.size()+2)/3)+1,'\0');int n=EVP_EncodeBlock((unsigned char*)&o[0],(const unsigned char*)s.data(),s.size());o.resize(n);string r;for(size_t i=0;i<o.size();i+=76)r+=o.substr(i,76)+"\r\n";return r;}
string pdfEsc(const string&s){string o;for(unsigned char c:s){if(c>126||c<32)o+='?';else{if(c=='('||c==')'||c=='\\')o+='\\';o+=(char)c;}}return o;}
// Builds a one-page landscape PDF certificate by hand (no external PDF library needed)
string makePdf(const string&name,const string&ev,const string&date,const string&cid,const string&college,const string&issued){
 ostringstream c;
 auto T=[&](const string&t,double cx,double y,double sz,const char*f,double r,double g,double b){double w=t.size()*sz*0.52;c<<"BT /"<<f<<" "<<sz<<" Tf "<<r<<" "<<g<<" "<<b<<" rg "<<(cx-w/2)<<" "<<y<<" Td ("<<pdfEsc(t)<<") Tj ET\n";};
 c<<"0.43 0.16 0.85 rg 0 535 842 60 re f\n0.31 0.27 0.9 RG 4 w 24 24 794 547 re S\n0.93 0.28 0.6 RG 1.5 w 34 34 774 527 re S\n";
 T(college,421,556,22,"F2",1,1,1);
 T("CERTIFICATE OF PARTICIPATION",421,470,34,"F2",0.06,0.1,0.24);
 T("This is to certify that",421,415,16,"F1",0.3,0.3,0.4);
 T(name,421,362,36,"F2",0.43,0.16,0.85);
 T("has successfully participated in",421,318,16,"F1",0.3,0.3,0.4);
 T(ev,421,272,26,"F2",0.06,0.1,0.24);
 T("held on "+date,421,238,16,"F1",0.3,0.3,0.4);
 c<<"0.2 w 0 0 0 RG 110 125 m 330 125 l S 512 125 m 732 125 l S\n";
 T("Authorized Signatory",220,108,12,"F1",0.3,0.3,0.4);T("EventSphere",622,108,12,"F2",0.43,0.16,0.85);
 T("Certificate ID: "+cid+"   |   Issued: "+issued,421,58,11,"F1",0.4,0.4,0.5);
 string s=c.str(),out="%PDF-1.4\n";vector<size_t> off;
 auto obj=[&](const string&b){off.push_back(out.size());out+=to_string(off.size())+" 0 obj\n"+b+"\nendobj\n";};
 obj("<</Type/Catalog/Pages 2 0 R>>");obj("<</Type/Pages/Kids[3 0 R]/Count 1>>");
 obj("<</Type/Page/Parent 2 0 R/MediaBox[0 0 842 595]/Resources<</Font<</F1 4 0 R/F2 5 0 R>>>>/Contents 6 0 R>>");
 obj("<</Type/Font/Subtype/Type1/BaseFont/Helvetica/Encoding/WinAnsiEncoding>>");obj("<</Type/Font/Subtype/Type1/BaseFont/Helvetica-Bold/Encoding/WinAnsiEncoding>>");
 obj("<</Length "+to_string(s.size())+">>\nstream\n"+s+"endstream");
 size_t x=out.size();out+="xref\n0 7\n0000000000 65535 f \n";char buf[32];for(size_t o:off){snprintf(buf,32,"%010zu 00000 n \n",o);out+=buf;}
 out+="trailer\n<</Size 7/Root 1 0 R>>\nstartxref\n"+to_string(x)+"\n%%EOF\n";return out;}
struct Up{const string*s;size_t p=0;};
size_t rdcb(char*b,size_t sz,size_t n,void*u){Up*x=(Up*)u;size_t m=min(sz*n,x->s->size()-x->p);memcpy(b,x->s->data()+x->p,m);x->p+=m;return m;}
// Real SMTP delivery through libcurl. Returns "sent", "test_mode" (no SMTP configured) or an error text.
string sendMail(const string&to,const string&name,const string&ev,const string&pdf,const string&fname){
 string url=genv("SMTP_URL"),user=genv("SMTP_USER"),pass=genv("SMTP_PASS"),from=genv("SMTP_FROM",user.c_str());
 if(url.empty())return "test_mode";
 string bd="ES"+rnd(8);
 string msg="From: EventSphere <"+from+">\r\nTo: "+to+"\r\nSubject: Your EventSphere Participation Certificate\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=\""+bd+"\"\r\n\r\n--"+bd+"\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nHi "+name+",\r\n\r\nThank you for attending "+ev+". Your participation certificate is attached.\r\n\r\nRegards,\r\nEventSphere\r\n\r\n--"+bd+"\r\nContent-Type: application/pdf; name=\""+fname+"\"\r\nContent-Transfer-Encoding: base64\r\nContent-Disposition: attachment; filename=\""+fname+"\"\r\n\r\n"+b64(pdf)+"\r\n--"+bd+"--\r\n";
 CURL*c=curl_easy_init();if(!c)return "curl init failed";Up up{&msg};
 curl_slist*rc=curl_slist_append(nullptr,("<"+to+">").c_str());string mf="<"+from+">";
 curl_easy_setopt(c,CURLOPT_URL,url.c_str());curl_easy_setopt(c,CURLOPT_USERNAME,user.c_str());curl_easy_setopt(c,CURLOPT_PASSWORD,pass.c_str());
 curl_easy_setopt(c,CURLOPT_MAIL_FROM,mf.c_str());curl_easy_setopt(c,CURLOPT_MAIL_RCPT,rc);curl_easy_setopt(c,CURLOPT_USE_SSL,(long)CURLUSESSL_ALL);
 curl_easy_setopt(c,CURLOPT_READFUNCTION,rdcb);curl_easy_setopt(c,CURLOPT_READDATA,&up);curl_easy_setopt(c,CURLOPT_UPLOAD,1L);curl_easy_setopt(c,CURLOPT_TIMEOUT,40L);
 CURLcode r=curl_easy_perform(c);curl_slist_free_all(rc);curl_easy_cleanup(c);
 return r==CURLE_OK?"sent":string(curl_easy_strerror(r));}
int main(){
 auto env=[](const char*k,const char*d){const char*v=getenv(k);return string(v?v:d);};
 Db db(env("DB_PATH","database/eventsphere.db"));
 {ifstream f("database/schema.sql");stringstream ss;ss<<f.rdbuf();db.exec(ss.str());}
 try{db.exec("ALTER TABLE registrations ADD COLUMN qr_token TEXT");}catch(...){}
 db.exec("CREATE UNIQUE INDEX IF NOT EXISTS idx_reg_qr ON registrations(qr_token)");
 for(auto&r:db.q("SELECT id FROM registrations WHERE qr_token IS NULL"))db.q("UPDATE registrations SET qr_token=? WHERE id=?",{rnd(16),to_string(r["id"].get<long long>())});
 string ae=env("ADMIN_EMAIL",""),ap=env("ADMIN_PASSWORD","");
 if(!ae.empty()&&ap.size()>=8&&db.q("SELECT id FROM users WHERE email=?",{ae}).empty())
  db.q("INSERT INTO users(name,email,password_hash,role) VALUES('Administrator',?,?,'admin')",{ae,hashPw(ap,rnd(16))});
 map<string,long long> sess;mutex mu;Server svr;
 const string TODAY="date('now','+"+env("UTC_OFFSET_MIN","330")+" minutes')";
 string certDir=env("CERT_DIR","certificates");filesystem::create_directories(certDir);curl_global_init(CURL_GLOBAL_DEFAULT);
 const string secret=rnd(32);
 // short-lived (60 s window) signed token shown in the organizer's live event QR
 auto ctok=[&](const string&eid,long long w){string d=eid+":"+to_string(w);unsigned char o[32];unsigned n=0;HMAC(EVP_sha256(),secret.data(),secret.size(),(const unsigned char*)d.data(),d.size(),o,&n);return hex(o,10);};
 // ---- in-app notifications ----
 auto notify=[&](const string&uid,const string&m){db.q("INSERT INTO notifications(user_id,message) VALUES(?,?)",{uid,m});};
 auto notifyRole=[&](const string&role,const string&m,const string&except){db.q("INSERT INTO notifications(user_id,message) SELECT id,? FROM users WHERE role=? AND id<>?",{m,role,except});};
 // ---- certificate email runs in a background thread so scanning stays instant ----
 auto deliver=[&](string cid,string to,string name,string ev,string pdf){thread([&db,&mu,cid,to,name,ev,pdf]{string st=sendMail(to,name,ev,pdf,cid+".pdf"),err;
  if(st!="sent"&&st!="test_mode"){err=st;st="failed";}lock_guard<mutex> l(mu);try{db.q("UPDATE certificates SET email_status=?,email_error=? WHERE cert_id=?",{st,err,cid});}catch(...){}}).detach();};
 auto auth=[&](const Request&q)->unique_ptr<User>{string c=q.get_header_value("Cookie");auto p=c.find("sid=");if(p==string::npos)return nullptr;
  auto it=sess.find(c.substr(p+4,64));if(it==sess.end())return nullptr;
  auto r=db.q("SELECT id,name,email,role FROM users WHERE id=?",{to_string(it->second)});return r.empty()?nullptr:makeUser(r[0]);};
 auto need=[&](const Request&q,function<bool(const User&)> ok){auto u=auth(q);if(!u)throw HttpErr{401,"Please log in"};if(!ok(*u))throw HttpErr{403,"You are not allowed to do this"};return u;};
 auto route=[&](bool post,const char*p,function<json(const Request&,json&)> fn){
  auto h=[&,fn](const Request&q,Response&r){lock_guard<mutex> l(mu);
   auto fail=[&](int c,const string&m){try{db.exec("ROLLBACK");}catch(...){}r.status=c;r.set_content(json{{"error",m}}.dump(),"application/json");};
   try{json b=json::object();if(!q.body.empty()){b=json::parse(q.body,nullptr,false);if(b.is_discarded())throw HttpErr{400,"Invalid JSON"};}
    json o=fn(q,b);if(o.contains("_raw")){r.status=200;r.set_header("Content-Disposition",o["_name"].get<string>());r.set_content(o["_raw"].get<string>(),"application/pdf");return;}r.status=o.value("_status",200);if(o.contains("_cookie"))r.set_header("Set-Cookie",o["_cookie"].get<string>());
    o.erase("_status");o.erase("_cookie");r.set_content(o.dump(),"application/json");}
   catch(HttpErr&x){fail(x.code,x.msg);} catch(exception&x){cerr<<"error: "<<x.what()<<endl;fail(500,"Server error");}};
  if(post)svr.Post(p,h);else svr.Get(p,h);};
 auto str=[](json&b,const char*k){return b.contains(k)&&b[k].is_string()?b[k].get<string>():string();};
 const string EV="SELECT e.*,u.name organizer,(SELECT COUNT(*) FROM registrations r WHERE r.event_id=e.id AND r.status='confirmed') taken FROM events e JOIN users u ON u.id=e.organizer_id ";
 // ---- auth ----
 route(true,"/api/signup",[&](const Request&,json&b){string n=str(b,"name"),e=str(b,"email"),p=str(b,"password"),r=str(b,"role");
  if(n.empty()||e.find('@')==string::npos||e.find_first_of(" \r\n<>")!=string::npos)throw HttpErr{400,"Name and a valid email are required"};
  if(p.size()<8)throw HttpErr{400,"Password must be at least 8 characters"};
  if(r!="student"&&r!="organizer")throw HttpErr{400,"Role must be student or organizer"};
  if(!db.q("SELECT id FROM users WHERE email=?",{e}).empty())throw HttpErr{409,"Email already registered"};
  db.q("INSERT INTO users(name,email,password_hash,role) VALUES(?,?,?,?)",{n,e,hashPw(p,rnd(16)),r});return json{{"_status",201},{"message","Account created"}};});
 route(true,"/api/login",[&](const Request&,json&b){auto r=db.q("SELECT * FROM users WHERE email=?",{str(b,"email")});
  if(r.empty()||!checkPw(str(b,"password"),r[0]["password_hash"]))throw HttpErr{401,"Invalid email or password"};
  string t=rnd(32);sess[t]=r[0]["id"];return json{{"_cookie","sid="+t+"; Path=/; HttpOnly; SameSite=Strict"},{"user",{{"name",r[0]["name"]},{"role",r[0]["role"]}}}};});
 route(true,"/api/logout",[&](const Request&q,json&){string c=q.get_header_value("Cookie");auto p=c.find("sid=");if(p!=string::npos)sess.erase(c.substr(p+4,64));
  return json{{"_cookie","sid=; Path=/; Max-Age=0"},{"ok",true}};});
 route(false,"/api/me",[&](const Request&q,json&){auto u=auth(q);if(!u)return json{{"user",nullptr}};return json{{"user",{{"name",u->name},{"email",u->email},{"role",u->role}}}};});
 // ---- events ----
 static const set<string> cats={"Technical","Workshop","Seminar","Cultural","Sports","Hackathon","Other"};
 auto fields=[&](json&b){vector<string> v;
  for(auto k:{"title","description","category","banner","venue","event_date","start_time","end_time","reg_open","reg_close","capacity","eligibility","contact"})
   v.push_back(b.contains(k)?(b[k].is_string()?b[k].get<string>():b[k].dump()):"");
  if(v[0].empty()||v[4].empty())throw HttpErr{400,"Title and venue are required"};
  if(!cats.count(v[2]))throw HttpErr{400,"Invalid category"};
  for(int i:{5,8,9})if(v[i].size()!=10)throw HttpErr{400,"Dates must be YYYY-MM-DD"};
  if(v[8]>v[9]||v[9]>v[5])throw HttpErr{400,"Registration window must open before it closes, and close on or before the event date"};
  int cap=atoi(v[10].c_str());if(cap<1||cap>100000)throw HttpErr{400,"Capacity must be 1-100000"};v[10]=to_string(cap);return v;};
 route(false,"/api/events",[&](const Request&q,json&){string sql=EV+"WHERE e.status='published'";vector<string> p;
  if(q.has_param("category")&&!q.get_param_value("category").empty()){sql+=" AND e.category=?";p.push_back(q.get_param_value("category"));}
  if(q.has_param("q")&&!q.get_param_value("q").empty()){sql+=" AND (e.title LIKE ? OR e.description LIKE ?)";string s="%"+q.get_param_value("q")+"%";p.push_back(s);p.push_back(s);}
  return json{{"events",db.q(sql+" ORDER BY e.event_date",p)}};});
 route(true,"/api/events",[&](const Request&q,json&b){auto u=need(q,[](const User&x){return x.canManageEvents();});auto v=fields(b);v.insert(v.begin(),to_string(u->id));
  db.exec("BEGIN IMMEDIATE");db.q("INSERT INTO events(organizer_id,title,description,category,banner,venue,event_date,start_time,end_time,reg_open,reg_close,capacity,eligibility,contact) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",v);
  db.q("INSERT INTO event_approval_history(event_id,actor_id,action) VALUES(?,?,'submitted')",{to_string(db.lastId()),to_string(u->id)});notifyRole("admin","New event proposal: "+v[1]+" by "+u->name,"0");db.exec("COMMIT");
  return json{{"_status",201},{"message","Proposal submitted for approval"}};});
 route(true,R"(/api/events/(\d+)/update)",[&](const Request&q,json&b){auto u=need(q,[](const User&x){return x.role=="organizer";});string id=q.matches[1];auto v=fields(b);
  if(db.q("SELECT id FROM events WHERE id=? AND organizer_id=?",{id,to_string(u->id)}).empty())throw HttpErr{404,"Event not found"};
  v.push_back(id);db.exec("BEGIN IMMEDIATE");
  db.q("UPDATE events SET title=?,description=?,category=?,banner=?,venue=?,event_date=?,start_time=?,end_time=?,reg_open=?,reg_close=?,capacity=?,eligibility=?,contact=?,status='pending',updated_at=datetime('now') WHERE id=?",v);
  db.q("INSERT INTO event_approval_history(event_id,actor_id,action) VALUES(?,?,'resubmitted')",{id,to_string(u->id)});notifyRole("admin","Event updated for re-review: "+v[0],"0");db.exec("COMMIT");return json{{"message","Event updated and sent for re-review"}};});
 route(false,"/api/my/events",[&](const Request&q,json&){auto u=need(q,[](const User&x){return x.role=="organizer";});
  return json{{"events",db.q(EV+"WHERE e.organizer_id=? ORDER BY e.id DESC",{to_string(u->id)})}};});
 route(false,"/api/admin/events",[&](const Request&q,json&){need(q,[](const User&x){return x.canReview();});
  return json{{"events",db.q(EV+"ORDER BY (e.status='pending') DESC,e.id DESC")}};});
 route(true,R"(/api/admin/events/(\d+)/review)",[&](const Request&q,json&b){auto u=need(q,[](const User&x){return x.canReview();});string id=q.matches[1],a=str(b,"action"),why=str(b,"reason");
  static const map<string,string> st={{"approve","published"},{"reject","rejected"},{"changes","changes_requested"}};
  if(!st.count(a))throw HttpErr{400,"Action must be approve, reject or changes"};if(a!="approve"&&why.empty())throw HttpErr{400,"A reason is required"};
  auto ev=db.q("SELECT title,organizer_id,event_date FROM events WHERE id=?",{id});if(ev.empty())throw HttpErr{404,"Event not found"};
  db.exec("BEGIN IMMEDIATE");db.q("UPDATE events SET status=? WHERE id=?",{st.at(a),id});
  db.q("INSERT INTO event_approval_history(event_id,actor_id,action,reason) VALUES(?,?,?,?)",{id,to_string(u->id),a,why});{string T=ev[0]["title"],org=to_string(ev[0]["organizer_id"].get<long long>());
   notify(org,"Your event \""+T+"\" was "+(a=="approve"?string("approved and published"):a=="reject"?"rejected: "+why:"sent back for changes: "+why));
   if(a=="approve"){string m="New event: "+T+" on "+ev[0]["event_date"].get<string>();notifyRole("student",m,"0");notifyRole("organizer",m,org);}}
  db.exec("COMMIT");return json{{"message","Event "+st.at(a)}};});
 route(false,"/api/admin/stats",[&](const Request&q,json&){need(q,[](const User&x){return x.canReview();});
  return json{{"stats",db.q("SELECT (SELECT COUNT(*) FROM users) users,(SELECT COUNT(*) FROM events WHERE status='pending') pending,(SELECT COUNT(*) FROM events WHERE status='published') published,(SELECT COUNT(*) FROM registrations WHERE status='confirmed') registrations,(SELECT COUNT(*) FROM attendance_records) attended")[0]},
   {"byCategory",db.q("SELECT e.category,COUNT(r.id) n FROM events e LEFT JOIN registrations r ON r.event_id=e.id AND r.status='confirmed' GROUP BY e.category")}};});
 // ---- registration (capacity enforced inside one IMMEDIATE transaction) ----
 route(true,R"(/api/events/(\d+)/register)",[&](const Request&q,json&){auto u=need(q,[](const User&x){return x.canRegister();});string id=q.matches[1],uid=to_string(u->id);
  db.exec("BEGIN IMMEDIATE");
  auto e=db.q("SELECT capacity,status,organizer_id,title,reg_open<="+TODAY+" AND reg_close>="+TODAY+" open FROM events WHERE id=?",{id});
  if(e.empty()||e[0]["status"]!="published")throw HttpErr{404,"Event not available"};
  if(e[0]["open"]!=1)throw HttpErr{409,"Registration is not open for this event"};
  auto ex=db.q("SELECT id,status FROM registrations WHERE event_id=? AND student_id=?",{id,uid});
  if(!ex.empty()&&ex[0]["status"]=="confirmed")throw HttpErr{409,"You are already registered"};
  if(db.q("SELECT COUNT(*) c FROM registrations WHERE event_id=? AND status='confirmed'",{id})[0]["c"].get<long long>()>=e[0]["capacity"].get<long long>())throw HttpErr{409,"This event is full"};
  string code="REG-"+rnd(4);for(auto&c:code)c=toupper(c);
  if(ex.empty())db.q("INSERT INTO registrations(reg_code,event_id,student_id,qr_token) VALUES(?,?,?,?)",{code,id,uid,rnd(16)});
  else db.q("UPDATE registrations SET status='confirmed',reg_code=?,qr_token=? WHERE id=?",{code,rnd(16),to_string(ex[0]["id"].get<long long>())});
  notify(to_string(e[0]["organizer_id"].get<long long>()),u->name+" registered for "+e[0]["title"].get<string>());db.exec("COMMIT");return json{{"_status",201},{"reg_code",code},{"message","Registration confirmed"}};});
 route(true,R"(/api/registrations/(\d+)/cancel)",[&](const Request&q,json&){auto u=need(q,[](const User&x){return x.canRegister();});
  if(db.q("SELECT id FROM registrations WHERE id=? AND student_id=? AND status='confirmed'",{q.matches[1],to_string(u->id)}).empty())throw HttpErr{404,"Registration not found"};
  db.q("UPDATE registrations SET status='cancelled' WHERE id=?",{q.matches[1]});return json{{"message","Registration cancelled"}};});
 route(false,"/api/my/registrations",[&](const Request&q,json&){auto u=need(q,[](const User&x){return x.canRegister();});
  return json{{"registrations",db.q("SELECT r.id,r.reg_code,r.qr_token,r.status,e.title,e.venue,e.event_date,e.start_time,a.checked_in_at,c.cert_id,c.email_status,e.event_date="+TODAY+" is_today FROM registrations r JOIN events e ON e.id=r.event_id LEFT JOIN attendance_records a ON a.registration_id=r.id LEFT JOIN certificates c ON c.registration_id=r.id WHERE r.student_id=? ORDER BY e.event_date DESC",{to_string(u->id)})}};});
 auto owns=[&](const User&u,const string&eid){auto e=db.q("SELECT organizer_id FROM events WHERE id=?",{eid});if(e.empty())throw HttpErr{404,"Event not found"};if(u.role!="admin"&&e[0]["organizer_id"].get<long long>()!=u.id)throw HttpErr{403,"This is not your event"};};
 // ---- QR attendance: token (or manual reg ID) is validated against the DB inside one transaction ----
 auto doCheck=[&](string eid,string t,string up,long long by)->json{
  if(db.q("SELECT 1 x FROM events WHERE id=? AND event_date="+TODAY,{eid}).empty())throw HttpErr{409,"Check-in is only open on the event date"};
  db.exec("BEGIN IMMEDIATE");
  auto r=db.q("SELECT r.id,r.event_id,r.status,r.reg_code,u.name FROM registrations r JOIN users u ON u.id=r.student_id WHERE r.qr_token=? OR r.reg_code=?",{t,up});
  if(r.empty())throw HttpErr{404,"Invalid QR code"};
  if(to_string(r[0]["event_id"].get<long long>())!=eid)throw HttpErr{409,"This QR is for a different event"};
  if(r[0]["status"]!="confirmed")throw HttpErr{409,"Registration was cancelled"};
  string rid=to_string(r[0]["id"].get<long long>());json o={{"name",r[0]["name"]},{"reg_code",r[0]["reg_code"]}};
  auto a=db.q("SELECT checked_in_at FROM attendance_records WHERE registration_id=?",{rid});
  bool had=!a.empty();auto cc=db.q("SELECT cert_id FROM certificates WHERE registration_id=?",{rid});
  if(had&&!cc.empty()){db.exec("COMMIT");o["result"]="already";o["time"]=a[0]["checked_in_at"];o["certificate"]=cc[0]["cert_id"];return o;}
  if(!had)db.q("INSERT INTO attendance_records(registration_id,event_id,checked_in_by) VALUES(?,?,?)",{rid,eid,to_string(by)});
  auto d=db.q("SELECT u.id uid,u.name,u.email,e.title,e.event_date FROM registrations r JOIN users u ON u.id=r.student_id JOIN events e ON e.id=r.event_id WHERE r.id=?",{rid})[0];
  string cid="CERT-"+rnd(5);for(auto&ch:cid)ch=toupper(ch);string issued=db.q("SELECT date('now') d")[0]["d"];
  string pdf=makePdf(d["name"],d["title"],d["event_date"],cid,env("COLLEGE_NAME","Your College Name"),issued),path=certDir+"/"+cid+".pdf";{ofstream f(path,ios::binary);f<<pdf;}
  db.q("INSERT INTO certificates(cert_id,registration_id,file_path) VALUES(?,?,?)",{cid,rid,path});
  notify(to_string(d["uid"].get<long long>()),"Attendance marked for \""+d["title"].get<string>()+"\". Your certificate is ready ("+cid+").");
  db.exec("COMMIT");deliver(cid,d["email"],d["name"],d["title"],pdf);o["result"]=had?"already":"ok";o["certificate"]=cid;return o;};
 route(true,"/api/attendance/check",[&](const Request&q,json&b){auto u=need(q,[](const User&x){return x.canManageEvents();});
  string eid=b.contains("event_id")?(b["event_id"].is_string()?b["event_id"].get<string>():b["event_id"].dump()):"",t=str(b,"token"),up=t;for(auto&c:up)c=toupper(c);
  owns(*u,eid);if(t.empty())throw HttpErr{400,"Scan a QR code or enter a registration ID"};
  if(db.q("SELECT 1 x FROM events WHERE id=? AND event_date="+TODAY,{eid}).empty())throw HttpErr{409,"Check-in is only open on the event date"};
  return doCheck(eid,t,up,u->id);});
 route(false,R"(/api/events/(\d+)/participants)",[&](const Request&q,json&){auto u=need(q,[](const User&x){return x.canManageEvents();});string eid=q.matches[1];owns(*u,eid);
  return json{{"participants",db.q("SELECT u.name,u.email,r.reg_code,r.status,a.checked_in_at,c.cert_id,c.email_status FROM registrations r JOIN users u ON u.id=r.student_id LEFT JOIN attendance_records a ON a.registration_id=r.id LEFT JOIN certificates c ON c.registration_id=r.id WHERE r.event_id=? ORDER BY u.name",{eid})}};});
 route(false,"/api/notifications",[&](const Request&q,json&){auto u=need(q,[](const User&){return true;});string id=to_string(u->id);
  return json{{"notifications",db.q("SELECT id,message,is_read,created_at FROM notifications WHERE user_id=? ORDER BY id DESC LIMIT 30",{id})},{"unread",db.q("SELECT COUNT(*) c FROM notifications WHERE user_id=? AND is_read=0",{id})[0]["c"]}};});
 route(true,"/api/notifications/read",[&](const Request&q,json&){auto u=need(q,[](const User&){return true;});db.q("UPDATE notifications SET is_read=1 WHERE user_id=?",{to_string(u->id)});return json{{"ok",true}};});
 route(false,"/api/certificates/verify/(.+)",[&](const Request&q,json&){string id=q.matches[1];for(auto&ch:id)ch=toupper(ch);
  auto c=db.q("SELECT c.issued_at,u.name,e.title,e.event_date FROM certificates c JOIN registrations r ON r.id=c.registration_id JOIN users u ON u.id=r.student_id JOIN events e ON e.id=r.event_id WHERE c.cert_id=?",{id});
  if(c.empty())throw HttpErr{404,"No certificate found with this ID"};
  return json{{"valid",true},{"name",c[0]["name"]},{"event",c[0]["title"]},{"date",c[0]["event_date"]},{"issued",c[0]["issued_at"]}};});
 route(false,R"(/api/certificates/([A-Za-z0-9-]+)/download)",[&](const Request&q,json&){auto u=need(q,[](const User&){return true;});string cid=q.matches[1];
  auto c=db.q("SELECT c.file_path,r.student_id,e.organizer_id FROM certificates c JOIN registrations r ON r.id=c.registration_id JOIN events e ON e.id=r.event_id WHERE c.cert_id=?",{cid});
  if(c.empty())throw HttpErr{404,"Certificate not found"};
  long long s=c[0]["student_id"],o=c[0]["organizer_id"];if(u->id!=s&&u->id!=o&&u->role!="admin")throw HttpErr{403,"Not allowed"};
  ifstream f(c[0]["file_path"].get<string>(),ios::binary);stringstream ss;ss<<f.rdbuf();
  return json{{"_raw",ss.str()},{"_name","attachment; filename=\""+cid+".pdf\""}};});
 route(true,R"(/api/certificates/([A-Za-z0-9-]+)/resend)",[&](const Request&q,json&){auto u=need(q,[](const User&x){return x.canManageEvents();});string cid=q.matches[1];
  auto c=db.q("SELECT c.file_path,e.id eid,e.title,u.name,u.email FROM certificates c JOIN registrations r ON r.id=c.registration_id JOIN events e ON e.id=r.event_id JOIN users u ON u.id=r.student_id WHERE c.cert_id=?",{cid});
  if(c.empty())throw HttpErr{404,"Certificate not found"};owns(*u,to_string(c[0]["eid"].get<long long>()));
  ifstream f(c[0]["file_path"].get<string>(),ios::binary);stringstream ss;ss<<f.rdbuf();
  db.q("UPDATE certificates SET email_status='pending',email_error=NULL WHERE cert_id=?",{cid});
  deliver(cid,c[0]["email"],c[0]["name"],c[0]["title"],ss.str());return json{{"message","Email retry started"}};});
 route(false,"/api/public/stats",[&](const Request&,json&){return json{{"stats",db.q("SELECT (SELECT COUNT(*) FROM events WHERE status='published') events,(SELECT COUNT(*) FROM registrations WHERE status='confirmed') registrations,(SELECT COUNT(*) FROM certificates) certificates")[0]}};});
 route(false,R"(/api/events/(\d+)/checkin-qr)",[&](const Request&q,json&){auto u=need(q,[](const User&x){return x.canManageEvents();});string eid=q.matches[1];owns(*u,eid);
  auto ev=db.q("SELECT title,event_date,event_date="+TODAY+" is_today FROM events WHERE id=?",{eid});
  return json{{"token",ctok(eid,(long long)time(nullptr)/300)},{"title",ev[0]["title"]},{"event_date",ev[0]["event_date"]},{"is_today",ev[0]["is_today"]}};});
 route(true,"/api/attendance/self",[&](const Request&q,json&b){auto u=need(q,[](const User&x){return x.canRegister();});
  string eid=b.contains("event_id")?(b["event_id"].is_string()?b["event_id"].get<string>():b["event_id"].dump()):"",t=str(b,"token");long long w=(long long)time(nullptr)/300;
  if(t.empty()||(ctok(eid,w)!=t&&ctok(eid,w-1)!=t))throw HttpErr{400,"This QR has expired. Scan the organizer's current QR again"};
  auto r=db.q("SELECT qr_token FROM registrations WHERE event_id=? AND student_id=? AND status='confirmed'",{eid,to_string(u->id)});
  if(r.empty())throw HttpErr{409,"You are not registered for this event"};
  string tok=r[0]["qr_token"];return doCheck(eid,tok,tok,u->id);});
 svr.set_mount_point("/",env("FRONTEND_DIR","frontend"));
 int port=stoi(env("PORT","8080"));cout<<"EventSphere running on port "<<port<<endl;svr.listen("0.0.0.0",port);}
