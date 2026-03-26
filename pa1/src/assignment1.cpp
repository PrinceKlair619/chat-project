#include <string>
#include <iostream>
#include <sstream>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <netdb.h>
#include <vector>
#include <algorithm>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/select.h>
#include <fcntl.h>
#include <errno.h>
#include <deque>
#include <unordered_map>
#include <unordered_set>
#include <cctype>
#include "../include/global.h"
#include "../include/logger.h"
#include "set"
#include <unordered_map>
#include <unordered_set>

struct ClientInfo {
    std::string hostname;
    std::string ip;
    int port;
    bool logged_in;
    int fd;
    bool exited;
    int msg_sent;
    int msg_rcv;
    std::set<std::string> blocked; 
};

static int serversock = -1;
static std::vector<ClientInfo> table;
static inline bool send_line(int fd, const std::string& s){
    std::string x = s; x.push_back('\n');
    ssize_t n = send(fd, x.c_str(), (ssize_t)x.size(), 0);
    return n == (ssize_t)x.size();
}
static bool recv_line(int fd, std::string& out){
    out.clear();
    char ch;
    while (true){
        ssize_t n = recv(fd, &ch, 1, 0);
        if (n <= 0) return false;
        if (ch == '\n') break;
        out.push_back(ch);
        if ((int)out.size() > 4096) break;
    }
    return true;
}
static std::string hostname_from_ip(const std::string& ip){
    sockaddr_in sa{}; sa.sin_family = AF_INET;
    if (inet_pton(AF_INET, ip.c_str(), &sa.sin_addr) != 1) return "";
    char host[NI_MAXHOST];
    if (getnameinfo((sockaddr*)&sa, sizeof(sa), host, sizeof(host),
                    nullptr, 0, NI_NAMEREQD) == 0)
        return std::string(host);
    return ip;
}
static bool valid_ipv4(const std::string& ip){
    sockaddr_in tmp{};
    return inet_pton(AF_INET, ip.c_str(), &tmp.sin_addr) == 1;
}
static bool validLoginArgs(const std::string& ip, const std::string& port){
    if (ip.empty() || port.empty()) return false;
    if (!valid_ipv4(ip)) return false;
    if (!std::all_of(port.begin(), port.end(), ::isdigit)) return false;
    long v = strtol(port.c_str(), nullptr, 10);
    return (v > 0 && v <= 65535);
}
static std::string getIp(){
    std::string ip;
    int s=socket(AF_INET,SOCK_DGRAM,0);
    if(s>=0){
        sockaddr_in dst{},me{};
        dst.sin_family=AF_INET; dst.sin_port=htons(53);
        inet_pton(AF_INET,"8.8.8.8",&dst.sin_addr);
        if(connect(s,(sockaddr*)&dst,sizeof(dst))==0){
            socklen_t len=sizeof(me);
            if(getsockname(s,(sockaddr*)&me,&len)==0){
                char buf[INET_ADDRSTRLEN];
                if(inet_ntop(AF_INET,&me.sin_addr,buf,sizeof(buf))) ip=buf;
            }
        }
        close(s);
    }
    return ip;
}
static void print_LIST(const char* tag, const std::vector<ClientInfo>& table){
    std::vector<ClientInfo> rows;
    for(const auto& c:table) if(c.logged_in) rows.push_back(c);
    std::sort(rows.begin(),rows.end(),[](const ClientInfo&a,const ClientInfo&b){
        if(a.port!=b.port) return a.port<b.port;
        if(a.hostname!=b.hostname) return a.hostname<b.hostname;
        return a.ip<b.ip;
    });
    cse4589_print_and_log("[%s:SUCCESS]\n", tag);
    int i=1;
    for(const auto& c:rows)
        cse4589_print_and_log("%-5d%-35s%-20s%-8d\n",
                              i++, c.hostname.c_str(), c.ip.c_str(), c.port);
    cse4589_print_and_log("[%s:END]\n", tag);
}
static bool update_client_list_from_server(int fd){
    char buf[4096];
    ssize_t n=recv(fd,buf,sizeof(buf)-1,0);
    if(n<=0) return false;
    buf[n]='\0';
    table.clear();
    std::istringstream iss(buf);
    std::string host, ip; int port;
    while(iss>>host>>ip>>port){
        ClientInfo entry;
        entry.hostname  = host;
        entry.ip        = ip;
        entry.port      = port;
        entry.logged_in = true;
        entry.fd        = -1;
        entry.exited    = false;
        entry.msg_sent  = 0;
        entry.msg_rcv   = 0;
        table.push_back(entry);
    }
    
    return true;
}
static bool send_client_list(int fd, const std::vector<ClientInfo>& table){
    std::ostringstream oss;
    for(const auto& c:table) if(c.logged_in)
        oss<<c.hostname<<" "<<c.ip<<" "<<c.port<<"\n";
    std::string data=oss.str();
    if(data.empty()) data="\n";
    return send(fd,data.c_str(),(ssize_t)data.size(),0)==(ssize_t)data.size();
}
static bool commonCMD(const std::string& cmd, char** argv){
    if(cmd=="AUTHOR"){
        cse4589_print_and_log("[AUTHOR:SUCCESS]\n");
        cse4589_print_and_log("I, %s, have read and understood the course academic integrity policy.\n","pklair-beibitzh");
        cse4589_print_and_log("[AUTHOR:END]\n");
        return true;
    }
    if(cmd=="IP"){
        std::string ip=getIp();
        if(ip.empty()||ip=="127.0.0.1"){ cse4589_print_and_log("[IP:ERROR]\n"); cse4589_print_and_log("[IP:END]\n"); }
        else { cse4589_print_and_log("[IP:SUCCESS]\n"); cse4589_print_and_log("IP:%s\n", ip.c_str()); cse4589_print_and_log("[IP:END]\n"); }
        return true;
    }
    if(cmd=="PORT"){
        cse4589_print_and_log("[PORT:SUCCESS]\n");
        cse4589_print_and_log("PORT:%s\n", argv[2]);
        cse4589_print_and_log("[PORT:END]\n");
        return true;
    }
    if(cmd=="EXIT"){
        cse4589_print_and_log("[EXIT:SUCCESS]\n");
        cse4589_print_and_log("[EXIT:END]\n");
        return true;
    }
    return false;
}
static void upsert_client_on_login(const std::string& host,
                                   const std::string& ip,
                                   int port,
                                   int fd){
    for(auto &c : table){
        if(c.ip == ip && c.port == port){
            c.hostname  = host;
            c.fd        = fd;
            c.logged_in = true;
            c.exited    = false;
            return;
        }
    }
    ClientInfo entry;
    entry.hostname  = host;
    entry.ip        = ip;
    entry.port      = port;
    entry.logged_in = true;
    entry.fd        = fd;
    entry.exited    = false;
    entry.msg_sent  = 0;
    entry.msg_rcv   = 0;
    table.push_back(entry);
}
static void print_STATISTICS(const std::vector<ClientInfo>& table){
    std::vector<const ClientInfo*> rows;
    for(const auto &c : table){
        if(!c.exited){
            rows.push_back(&c);
        }
    }
    std::sort(rows.begin(), rows.end(),
        [](const ClientInfo* a, const ClientInfo* b){
            if(a->port != b->port) return a->port < b->port;
            if(a->hostname != b->hostname) return a->hostname < b->hostname;
            return a->ip < b->ip;
        });
    cse4589_print_and_log("[STATISTICS:SUCCESS]\n");
    int i = 1;
    for(const ClientInfo* c : rows){
        const char* status = c->logged_in ? "logged-in" : "logged-out";
        cse4589_print_and_log("%-5d%-35s%-8d%-8d%-8s\n",
            i++,
            c->hostname.c_str(),
            c->msg_sent,
            c->msg_rcv,
            status
        );
    }
    cse4589_print_and_log("[STATISTICS:END]\n");
}

static bool local_has_logged_in_ip(const std::string& ip){
    for(const auto& c: table){
        if(c.logged_in && c.ip == ip) return true;
    }
    return false;
}

struct QueuedMsg { std::string from_ip; std::string text; };

// Per-destination-IP message buffers (deliver on login). Limit ~100 total if you want.
static std::unordered_map<std::string, std::deque<QueuedMsg>> buffered_msgs;

// receiver_ip -> set of blocked sender IPs
static std::unordered_map<std::string, std::unordered_set<std::string>> block_map;

static ClientInfo* find_by_fd(int fd){
    for(auto &c: table) if(c.fd==fd) return &c; return nullptr;
}
static ClientInfo* find_by_ip(const std::string& ip){
    for(auto &c: table) if(c.ip==ip) return &c; return nullptr;
}
static bool is_blocked(const std::string& dest_ip, const std::string& sender_ip){
    auto it = block_map.find(dest_ip);
    return it != block_map.end() && it->second.count(sender_ip) > 0;
}

void handle_BLOCKED(const std::string &qip,
    const std::vector<ClientInfo> &table,
    const std::unordered_map<std::string, std::unordered_set<std::string>> &block_map) {
if(!valid_ipv4(qip)){
cse4589_print_and_log("[BLOCKED:ERROR]\n");
cse4589_print_and_log("[BLOCKED:END]\n");
return;
}

bool known = false;
for(const auto &c : table) if(c.ip == qip){ known = true; break; }
if(!known){
cse4589_print_and_log("[BLOCKED:ERROR]\n");
cse4589_print_and_log("[BLOCKED:END]\n");
return;
}

struct Row { std::string host, ip; int port; };
std::vector<Row> rows;

auto it = block_map.find(qip);
if(it != block_map.end()){
for(const auto &c : table){
if(it->second.count(c.ip))
rows.push_back({c.hostname, c.ip, c.port}); // use c.host if that's your field name
}
}

std::sort(rows.begin(), rows.end(), [](const Row &a, const Row &b){ return a.port < b.port; });

cse4589_print_and_log("[BLOCKED:SUCCESS]\n");
int idx = 1;
for(const auto &r : rows){
cse4589_print_and_log("%-5d%-35s%-20s%-8d\n",
              idx++, r.host.c_str(), r.ip.c_str(), r.port);
}
cse4589_print_and_log("[BLOCKED:END]\n");
}

//main
int main(int argc, char **argv){
    cse4589_init_log(argv[2]);
    fclose(fopen(LOGFILE,"w"));
    bool isClient=(argv[1][0]=='c');

    if(isClient){
        bool logged_in=false;
        while(true){
            fd_set rfds;
            FD_ZERO(&rfds);
            FD_SET(STDIN_FILENO, &rfds);
            int maxfd = STDIN_FILENO;
            if(serversock >= 0){
                FD_SET(serversock, &rfds);
                if(serversock > maxfd) maxfd = serversock;
            }
            if(select(maxfd+1, &rfds, nullptr, nullptr, nullptr) < 0){
                continue;
            }
            if(serversock >= 0 && FD_ISSET(serversock, &rfds)){
                std::string line;
                if(!recv_line(serversock, line)){
                    close(serversock); serversock = -1; logged_in = false;
                }else{
                    if(line.rfind("M ", 0) == 0){
                        std::istringstream ss(line);
                        std::string tag, src_ip;
                        ss >> tag >> src_ip;
                    
                        std::string msg;
                        std::getline(ss, msg);
                        if(!msg.empty() && msg[0]==' ')
                            msg.erase(0,1);
                    
                        cse4589_print_and_log("[RECEIVED:SUCCESS]\n");
                        cse4589_print_and_log("msg from:%s\n", src_ip.c_str());
                        cse4589_print_and_log("[msg]:%s\n", msg.c_str());
                        cse4589_print_and_log("[RECEIVED:END]\n");
                    }
                    
                }
            }
            if(FD_ISSET(STDIN_FILENO, &rfds)){
                std::string line;
                if(!std::getline(std::cin, line)) break; // EOF
                if(line.empty()) continue;
                std::istringstream ss(line);
                std::string cmd; ss>>cmd;
                static std::unordered_set<std::string> local_blocked;

                if(!logged_in && cmd!="AUTHOR"&&cmd!="IP"&&cmd!="PORT"&&cmd!="LOGIN"&&cmd!="EXIT"){
                    cse4589_print_and_log("[%s:ERROR]\n", cmd.c_str());
                    cse4589_print_and_log("[%s:END]\n",   cmd.c_str());
                    continue;
                }
                if(commonCMD(cmd,argv)){
                    if(cmd=="EXIT"){
                        if(serversock>=0){
                            send_line(serversock, "EXITNOW");
                            close(serversock);
                            serversock=-1;
                        }
                        break;
                    }
                    continue;
                }                
                if(cmd=="LOGIN"){
                    std::string ipArg, portArg, extra;
                    if(!(ss>>ipArg>>portArg) || (ss>>extra) || !validLoginArgs(ipArg,portArg)){
                        cse4589_print_and_log("[LOGIN:ERROR]\n"); cse4589_print_and_log("[LOGIN:END]\n");
                        if(serversock>=0){ close(serversock); serversock=-1; }
                        continue;
                    }
                    int sockfd=socket(AF_INET,SOCK_STREAM,0);
                    sockaddr_in srv{}; srv.sin_family=AF_INET; srv.sin_port=htons(atoi(portArg.c_str()));
                    inet_pton(AF_INET,ipArg.c_str(),&srv.sin_addr);
                    if(sockfd<0 || connect(sockfd,(sockaddr*)&srv,sizeof(srv))!=0){
                        if(sockfd>=0) close(sockfd);
                        cse4589_print_and_log("[LOGIN:ERROR]\n"); cse4589_print_and_log("[LOGIN:END]\n"); continue;
                    }
                    serversock=sockfd;
                    int my_listen_port = atoi(argv[2]);
                    if(my_listen_port<=0 || !send_line(serversock, std::to_string(my_listen_port))){
                        cse4589_print_and_log("[LOGIN:ERROR]\n"); cse4589_print_and_log("[LOGIN:END]\n");
                        close(serversock); serversock=-1; continue;
                    }
                    if(update_client_list_from_server(serversock)){
                        cse4589_print_and_log("[LOGIN:SUCCESS]\n"); cse4589_print_and_log("[LOGIN:END]\n"); logged_in=true;
                    }else{
                        cse4589_print_and_log("[LOGIN:ERROR]\n"); cse4589_print_and_log("[LOGIN:END]\n");
                        close(serversock); serversock=-1;
                    }
                }
                else if(cmd=="REFRESH"){
                    if(!logged_in || serversock<0){
                        cse4589_print_and_log("[REFRESH:ERROR]\n"); cse4589_print_and_log("[REFRESH:END]\n");
                    }else{
                        if(send_line(serversock,"R") && update_client_list_from_server(serversock)){
                            cse4589_print_and_log("[REFRESH:SUCCESS]\n"); cse4589_print_and_log("[REFRESH:END]\n");
                        }else{
                            cse4589_print_and_log("[REFRESH:ERROR]\n"); cse4589_print_and_log("[REFRESH:END]\n");
                        }
                    }
                }
                else if(cmd=="LIST"){
                    if(!logged_in){ cse4589_print_and_log("[LIST:ERROR]\n"); cse4589_print_and_log("[LIST:END]\n"); }
                    else{ print_LIST("LIST", table); }
                }
                else if(cmd=="LOGOUT"){
                    if(!logged_in || serversock < 0){
                        cse4589_print_and_log("[LOGOUT:ERROR]\n");
                        cse4589_print_and_log("[LOGOUT:END]\n");
                    }else{
                        send_line(serversock, "LOGOUT");
                        close(serversock);
                        serversock = -1;
                        logged_in = false;
                        cse4589_print_and_log("[LOGOUT:SUCCESS]\n");
                        cse4589_print_and_log("[LOGOUT:END]\n");
                    }
                }
                else if(cmd=="SEND"){
                    if(!logged_in || serversock<0){
                        cse4589_print_and_log("[SEND:ERROR]\n"); cse4589_print_and_log("[SEND:END]\n");
                        continue;
                    }
                    std::string target_ip;
                    if(!(ss>>target_ip) || !valid_ipv4(target_ip)){
                        cse4589_print_and_log("[SEND:ERROR]\n"); cse4589_print_and_log("[SEND:END]\n");
                        continue;
                    }
                    std::string msg; std::getline(ss, msg);
                    if(!msg.empty() && msg[0]==' ') msg.erase(0,1);
                    if(msg.size() > 256){
                        cse4589_print_and_log("[SEND:ERROR]\n"); cse4589_print_and_log("[SEND:END]\n");
                        continue;
                    }
                    if(!local_has_logged_in_ip(target_ip)){
                        cse4589_print_and_log("[SEND:ERROR]\n"); cse4589_print_and_log("[SEND:END]\n");
                        continue;
                    }
                    std::ostringstream oss; oss << "S " << target_ip << " " << msg;
                    if(!send_line(serversock, oss.str())){
                        cse4589_print_and_log("[SEND:ERROR]\n"); cse4589_print_and_log("[SEND:END]\n");
                    }else{
                        cse4589_print_and_log("[SEND:SUCCESS]\n"); cse4589_print_and_log("[SEND:END]\n");
                    }
                }
                else if(cmd=="BROADCAST"){
                    if(!logged_in || serversock<0){
                        cse4589_print_and_log("[BROADCAST:ERROR]\n");
                        cse4589_print_and_log("[BROADCAST:END]\n");
                        continue;
                    }               
                    std::string msg;
                    std::getline(ss, msg);
                    if(!msg.empty() && msg[0]==' ')
                        msg.erase(0,1);            
                    if(msg.size() > 256){
                        cse4589_print_and_log("[BROADCAST:ERROR]\n");
                        cse4589_print_and_log("[BROADCAST:END]\n");
                        continue;
                    }
                    std::ostringstream oss;
                    oss << "B " << msg;
                    if(!send_line(serversock, oss.str())){
                        cse4589_print_and_log("[BROADCAST:ERROR]\n");
                        cse4589_print_and_log("[BROADCAST:END]\n");
                    } else {
                        cse4589_print_and_log("[BROADCAST:SUCCESS]\n");
                        cse4589_print_and_log("[BROADCAST:END]\n");
                    }
                }else if(cmd=="BLOCK"){
                    std::string ip; if(!(ss>>ip) || !valid_ipv4(ip)){
                        cse4589_print_and_log("[BLOCK:ERROR]\n"); cse4589_print_and_log("[BLOCK:END]\n");
                        continue;
                    }
                    bool exists_local = local_has_logged_in_ip(ip);
                    if(!exists_local || local_blocked.count(ip)){
                        cse4589_print_and_log("[BLOCK:ERROR]\n"); cse4589_print_and_log("[BLOCK:END]\n");
                        continue;
                    }
                    if(serversock<0){ cse4589_print_and_log("[BLOCK:ERROR]\n"); cse4589_print_and_log("[BLOCK:END]\n"); continue; }
                    send_line(serversock, std::string("BLK ")+ip);
                    local_blocked.insert(ip);
                    cse4589_print_and_log("[BLOCK:SUCCESS]\n"); cse4589_print_and_log("[BLOCK:END]\n");
                }
                else if(cmd=="UNBLOCK"){
                    std::string ip; if(!(ss>>ip) || !valid_ipv4(ip)){
                        cse4589_print_and_log("[UNBLOCK:ERROR]\n"); cse4589_print_and_log("[UNBLOCK:END]\n");
                        continue;
                    }
                    bool exists_local = local_has_logged_in_ip(ip);
                    if(!exists_local || !local_blocked.count(ip)){
                        cse4589_print_and_log("[UNBLOCK:ERROR]\n"); cse4589_print_and_log("[UNBLOCK:END]\n");
                        continue;
                    }
                    if(serversock<0){ cse4589_print_and_log("[UNBLOCK:ERROR]\n"); cse4589_print_and_log("[UNBLOCK:END]\n"); continue; }
                    send_line(serversock, std::string("UBLK ")+ip);
                    local_blocked.erase(ip);
                    cse4589_print_and_log("[UNBLOCK:SUCCESS]\n"); cse4589_print_and_log("[UNBLOCK:END]\n");
                }
                
                else{
                    cse4589_print_and_log("[%s:ERROR]\n", cmd.c_str());
                    cse4589_print_and_log("[%s:END]\n",   cmd.c_str());
                }
            } 
        } 
    } else {
        int listen_port=atoi(argv[2]);
        int server_fd=socket(AF_INET,SOCK_STREAM,0);
        int yes=1; setsockopt(server_fd,SOL_SOCKET,SO_REUSEADDR,&yes,sizeof(yes));
        sockaddr_in addr{}; addr.sin_family=AF_INET; addr.sin_addr.s_addr=INADDR_ANY; addr.sin_port=htons(listen_port);
        bind(server_fd,(sockaddr*)&addr,sizeof(addr));
        listen(server_fd,10);
        fd_set master,readfds;
        FD_ZERO(&master); FD_SET(server_fd,&master); FD_SET(STDIN_FILENO,&master);
        int fdmax=std::max(server_fd,STDIN_FILENO);
        bool running=true;
        while(running){
            readfds=master;
            if(select(fdmax+1,&readfds,nullptr,nullptr,nullptr)<0) continue;
            //server console commands
            if(FD_ISSET(STDIN_FILENO,&readfds)){
                std::string line; if(!std::getline(std::cin,line)) break;
                if(line.empty()) continue;
                std::istringstream ss(line); std::string cmd; ss>>cmd;
                if(cmd=="LOGIN"){ cse4589_print_and_log("[LOGIN:ERROR]\n"); cse4589_print_and_log("[LOGIN:END]\n"); continue; }
                if(commonCMD(cmd,argv)){ if(cmd=="EXIT") running=false; continue; }
                if(cmd=="LIST"){ print_LIST("LIST", table); continue; }
                if(cmd=="STATISTICS"){
                    print_STATISTICS(table);
                    continue;
                }
                if(cmd=="BLOCKED"){
                    std::string qip; ss >> qip;
                    handle_BLOCKED(qip, table, block_map);
                    continue;
                }
                
                cse4589_print_and_log("[%s:ERROR]\n", cmd.c_str()); cse4589_print_and_log("[%s:END]\n", cmd.c_str());
            }
            //new incoming client connection
            if(FD_ISSET(server_fd,&readfds)){
                sockaddr_in cli{}; socklen_t len=sizeof(cli);
                int cfd=accept(server_fd,(sockaddr*)&cli,&len);
                if(cfd<0) continue;
                std::string first;
                if(!recv_line(cfd, first)){ close(cfd); continue; }
                int listen_p = 0; try { listen_p = std::stoi(first); } catch(...) { listen_p = 0; }
                if(listen_p<=0 || listen_p>65535){ close(cfd); continue; }
                char ip[INET_ADDRSTRLEN]; inet_ntop(AF_INET,&cli.sin_addr,ip,sizeof(ip));
                std::string host=hostname_from_ip(ip);
                upsert_client_on_login(host, ip, listen_p, cfd);
                send_client_list(cfd,table);
                // Deliver buffered messages (if any) after list
                auto it = buffered_msgs.find(ip);
                if(it != buffered_msgs.end()){
                    for(const auto& qm : it->second){
                        // Skip if currently blocked (block applies to both relay and delivery)
                        if(is_blocked(ip, qm.from_ip)) continue;
                        std::ostringstream out; out << "M " << qm.from_ip << " " << qm.text;
                        send_line(cfd, out.str());
                        // Increment receiver's msg_rcv for statistics
                        if(ClientInfo* r = find_by_ip(ip)) r->msg_rcv += 1;
                    }
                    it->second.clear();
                }
                FD_SET(cfd,&master); if(cfd>fdmax) fdmax=cfd;
            }
            //handle client sockets
            for(int fd=0; fd<=fdmax; ++fd){
                if(fd==server_fd || fd==STDIN_FILENO) continue;
                if(!FD_ISSET(fd,&readfds)) continue;
                std::string req;
                if(!recv_line(fd, req)){
                    for(auto &c : table){
                        if(c.fd==fd){
                            c.logged_in = false;
                            c.fd = -1;
                            break;
                        }
                    }
                    close(fd); FD_CLR(fd,&master);
                    continue;
                }
                if(req=="R"){
                    send_client_list(fd, table);
                }
                else if(req=="LOGOUT"){
                    for(auto &c : table){
                        if(c.fd == fd){
                            c.logged_in = false;
                            c.fd = -1;
                            break;
                        }
                    }
                    close(fd);
                    FD_CLR(fd, &master);
                }
                else if(req=="EXITNOW"){
                    for(auto &c : table){
                        if(c.fd == fd){
                            c.logged_in = false;
                            c.fd        = -1;
                            c.exited    = true;
                            break;
                        }
                    }
                    close(fd);
                    FD_CLR(fd, &master);
                }
                
                else if(req.rfind("S ", 0) == 0){
                    std::istringstream ss(req);
                    std::string tag, dest_ip; ss >> tag >> dest_ip;
                    std::string msg; std::getline(ss, msg); if(!msg.empty() && msg[0]==' ') msg.erase(0,1);
                
                    ClientInfo* sender = find_by_fd(fd);
                    ClientInfo* dest   = find_by_ip(dest_ip);
                    std::string sender_ip = sender ? sender->ip : "0.0.0.0";
                
                    bool delivered = false, buffered = false;
                
                    if(dest){
                        // Drop if receiver blocks sender (no relay, no buffer)
                        if(!is_blocked(dest->ip, sender_ip) && !dest->exited){
                            if(dest->logged_in && dest->fd >= 0){
                                std::ostringstream out; out << "M " << sender_ip << " " << msg;
                                if(send_line(dest->fd, out.str())){
                                    delivered = true;
                                    dest->msg_rcv += 1;
                                }
                            } else {
                                // receiver offline -> buffer
                                buffered_msgs[dest->ip].push_back({sender_ip, msg});
                                buffered = true;
                            }
                        }
                    }
                    if(sender) sender->msg_sent += 1;
                
                    if(delivered || buffered){
                        cse4589_print_and_log("[RELAYED:SUCCESS]\n");
                        cse4589_print_and_log("msg from:%s, to:%s\n", sender_ip.c_str(), dest_ip.c_str());
                        cse4589_print_and_log("[msg]:%s\n", msg.c_str());
                        cse4589_print_and_log("[RELAYED:END]\n");
                    } else {
                        // Either invalid dest, dest EXITed, or blocked; spec doesn’t require error to sender.
                        cse4589_print_and_log("[RELAYED:ERROR]\n");
                        cse4589_print_and_log("[RELAYED:END]\n");
                    }
                }                
                else if(req.rfind("B ", 0) == 0){
                    std::string msg = req.substr(2);
                    if(!msg.empty() && msg[0]==' ') msg.erase(0,1);
                
                    ClientInfo* sender = find_by_fd(fd);
                    std::string sender_ip = sender ? sender->ip : "0.0.0.0";
                    bool any_action = false;
                
                    for(auto &dst : table){
                        if(!dst.logged_in && dst.exited) continue; // EXITed: ignore forever
                        if(sender && dst.ip == sender->ip) continue; // don't echo to sender
                        if(is_blocked(dst.ip, sender_ip)) continue;  // drop if blocked
                
                        if(dst.logged_in && dst.fd >= 0){
                            std::ostringstream out; out << "M " << sender_ip << " " << msg;
                            if(send_line(dst.fd, out.str())){
                                dst.msg_rcv += 1;
                                any_action = true;
                            }
                        } else {
                            // offline: buffer broadcast for this receiver
                            buffered_msgs[dst.ip].push_back({sender_ip, msg});
                            any_action = true;
                        }
                    }
                
                    if(sender) sender->msg_sent += 1;
                
                    if(any_action){
                        cse4589_print_and_log("[RELAYED:SUCCESS]\n");
                        cse4589_print_and_log("msg from:%s, to:%s\n", sender_ip.c_str(), "255.255.255.255");
                        cse4589_print_and_log("[msg]:%s\n", msg.c_str());
                        cse4589_print_and_log("[RELAYED:END]\n");
                    } else {
                        cse4589_print_and_log("[RELAYED:ERROR]\n");
                        cse4589_print_and_log("[RELAYED:END]\n");
                    }
                }
                else if(req.rfind("BLK ", 0) == 0){
                    // BLK <ip-to-block>
                    std::string target = req.substr(4);
                    if(!target.empty() && target[0]==' ') target.erase(0,1);
                    ClientInfo* who = find_by_fd(fd);
                    if(who){
                        block_map[who->ip].insert(target);
                    }
                    // No log required by spec; client prints result.
                }
                else if(req.rfind("UBLK ", 0) == 0){
                    std::string target = req.substr(5);
                    if(!target.empty() && target[0]==' ') target.erase(0,1);
                    ClientInfo* who = find_by_fd(fd);
                    if(who){
                        block_map[who->ip].erase(target);
                    }
                }
                else if(req.rfind("BLIST", 0) == 0){
                    ClientInfo* who = find_by_fd(fd);
                    std::ostringstream oss;
                    if(who){
                        auto it = block_map.find(who->ip);
                        if(it != block_map.end()){
                            std::vector<std::string> ips(it->second.begin(), it->second.end());
                            std::sort(ips.begin(), ips.end());
                            for(const auto& ip : ips) oss << ip << "\n";
                        }
                    }
                    oss << ".\n";
                    std::string data = oss.str();
                    send(fd, data.c_str(), (ssize_t)data.size(), 0);
                }
                                                    
            }
        }
        for(int fd=0; fd<=fdmax; ++fd) if(FD_ISSET(fd,&master)) close(fd);
    }
    return 0;
}