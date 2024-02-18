#include<bits/stdc++.h>
#include<net/if.h>
#include<arpa/inet.h>
#include<sys/socket.h>
#include<netinet/in.h>
#include <ifaddrs.h>
#include<pcap.h>
#include<errno.h>
#include<netinet/if_ether.h>
#include<net/ethernet.h>
#include<netinet/ether.h>
#include<netinet/udp.h>
#include<netinet/ip.h>//provides ip header
#include<netinet/tcp.h>//provide tcp header
#include<netinet/udp.h> //provides udp header
#include<netinet/ip_icmp.h>  //prvides icmp header

using namespace std;
void process_packet(u_char *, const struct pcap_pkthdr *, const u_char *);
void process_ip_packet(const u_char * , int);
void print_ip_packet(const u_char * , int);
void print_tcp_packet(const u_char *  , int );
void print_udp_packet(const u_char * , int);
void print_icmp_packet(const u_char * , int );
void print_other_packets(const u_char *, int);
void PrintData (const u_char * , int);

struct sockaddr_in source,dest;
int tcp=0,udp=0,icmp=0,others=0,igmp=0,total=0;
//sytten and user info
struct info{
    char *username;
    char hostname[128];
    char path[128];
};

// colors
static void red_color(void){
    cout<<"\e[0;31m";
}
static void green_color(void){
    cout<<"\e[0;32m";
}

static void magenta_color(void){
    cout<<"\e[0;35m";
}

static void reset_color(void){
    cout<<"\e[0;37m";
}

static void clear_screen(void){
    puts("\033[H\033[2JJ");
}

// header
static void header(void) {
    struct info *pb, uinfo;
    pb = &uinfo;
    pb->username = (char *)malloc(32 * sizeof(char));
    
    cuserid(pb->username);
    getcwd(pb->path, sizeof(pb->path));
    gethostname(pb->hostname, sizeof(pb->hostname));
    red_color();
    cout<<"\n                               Host Information";
    cout<<"\n		               ────────────────";
    cout<<"\n		               Hostname -> "<<pb->hostname;
    cout<<"\n		               Username -> "<<pb->username;
    cout<<"\n		               Path -> "<<pb->path;
    cout<<"\n";
    reset_color();
}

// list availbale interfaces

void list_interfaces(int &device,char devs[][100]){
    int ind=1;
     pcap_if_t *interface,*dev;
    char pcap_error[PCAP_ERRBUF_SIZE];

red_color();
cout<<"Finding devices.....\n";
reset_color();
int f=0;
if(pcap_findalldevs(&interface,pcap_error)){
    cout<<"Error in finding devices: "<<pcap_error<<endl;
    f=1;
}
red_color();
cout<<"Done!\n\n\n";
reset_color();
if(f==1)exit(1);

magenta_color();
cout<<"\nAvailabe devices are:\n";
reset_color();
green_color();
for(dev=interface;dev!=NULL;dev=dev->next){
    cout<<ind<<". "<<dev->name<<" - "<<"\n";
    if(dev->name!=NULL){
        strcpy(devs[ind],dev->name);
    }
    ind++;
}
reset_color();

cout<<"\nEnter the the device number you want to sniff: ";

int n;
cin>>n;

if(n>=ind||n<1){
    red_color();
    cout<<"\noops!...invalid device\n";
    reset_color();
    exit(1);
}
//memset(device,0,sizeof(device));
device=n;

}

// start sniffing
void sniffer(void){
    int i;
    char *iface;
    const u_char *up;
    char pcap_error[PCAP_ERRBUF_SIZE];

    // struct bpf_program fp;
    struct pcap_pkthdr hdr;

    int device;
    char devs[100][100];
    memset(devs,0,sizeof(devs));
    list_interfaces(device,devs);

    

    //pcap_lookupnet(iface,&bpp,&bp,pcap_error);


    pcap_t *handle;
    char errbuf[100];
    red_color();
    cout<<"\nopening the device to sniff.....\n";
    reset_color();
    cout<<device<<endl;
    handle=pcap_open_live(devs[device], 65535, 1, 0, errbuf);

    if(handle==NULL){
        red_color();
        cout<<"Couldn't open device: "<<device<<" "<<errbuf<<endl;
        exit(1);
    }
    pcap_loop(handle,0,process_packet,NULL);

}

int main(){
    header();
    cout<<"\n\n";
    sniffer();
    return 0;
}
void magenta_word(string word){
    magenta_color();
    cout<<word;
    reset_color();
}
void colored_line(void){
    red_color();
    for(int i=-0;i<18;i++){
        cout<<"-";
    }
    cout<<"\n";
    reset_color();
}
void vertical(void){
    red_color();
    cout<<"|";
    reset_color();
}
void process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *buffer)
{
    int size = header->len;
     
    //Get the IP Header part of this packet , excluding the ethernet header
    struct iphdr *iph = (struct iphdr*)(buffer + sizeof(struct ethhdr));
    static int total=0;
    switch (iph->protocol) //Check the Protocol and do accordingly...
    {
        case 1:  //ICMP Protocol
            ++icmp;
            ++total;
            print_icmp_packet( buffer , size);
            break;
         
        case 2:  //IGMP Protocol
            ++igmp;
            ++total;
            break;
         
        case 6:  //TCP Protocol
            ++tcp;
            ++total;
            print_tcp_packet(buffer , size);
            break;
         
        case 17: //UDP Protocol
            ++udp;
            ++total;
            print_udp_packet(buffer , size);
            break;
         
        default: //Some Other Protocol like ARP etc.
            ++total;
            ++others;
            print_other_packets(buffer,size);
            break;
    }
    cout<<endl;
    cout<<"\e[0;32mTCP: \e[0;37m"<<tcp<<"  \e[0;32m UDP: \e[0;37m"<<udp<<"  \e[0;32m ICMP: \e[0;37m"<<icmp;
    cout<<"  \e[0;32m IGMP: \e[0;37m"<<igmp<<"  \e[0;32m others: \e[0;37m"<<others;
    cout<<"  \e[0;32m TOTAL: \e[0;37m"<<total<<endl;

    red_color();
    cout<<"__________________________________________________________________\n";
    reset_color();

}
void print_ethernet_header(const u_char *Buffer, int Size)
{
    struct ethhdr *eth = (struct ethhdr *)Buffer;
     
    printf("\n");
    red_color();
    printf("Ethernet Header\n");
    reset_color();

    magenta_color();
    printf("Destination Address : ");
    reset_color();
    printf("%.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->h_dest[0] , eth->h_dest[1] , eth->h_dest[2] , eth->h_dest[3] , eth->h_dest[4] , eth->h_dest[5] );
    magenta_color();
    printf("Source Address      :");
    reset_color();
    printf("%.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->h_source[0] , eth->h_source[1] , eth->h_source[2] , eth->h_source[3] , eth->h_source[4] , eth->h_source[5] );
    magenta_color();
    printf("Protocol            : ");
    reset_color();
    printf("%u \n",(unsigned short)eth->h_proto);
}
 
void print_ip_header(const u_char * Buffer, int Size)
{
    print_ethernet_header(Buffer , Size);
   
    unsigned short iphdrlen;
         
    struct iphdr *iph = (struct iphdr *)(Buffer  + sizeof(struct ethhdr) );
    iphdrlen =iph->ihl*4;
     
    memset(&source, 0, sizeof(source));
    source.sin_addr.s_addr = iph->saddr;
     
    memset(&dest, 0, sizeof(dest));
    dest.sin_addr.s_addr = iph->daddr;
     
    printf("\n");
    red_color();
    printf("IP Header\n");
    reset_color();

    magenta_color();
    printf("IP Version        : ");
    reset_color();
    printf("%d\n",(unsigned int)iph->version);

    magenta_color();
    printf("IP Header Length  : ");
    reset_color();
    printf("%d DWORDS or %d Bytes\n",(unsigned int)iph->ihl,((unsigned int)(iph->ihl))*4);

    magenta_color();
    printf("Type Of Service   : ");
    reset_color();
    printf("%d\n",(unsigned int)iph->tos);

    magenta_color();
    printf("IP Total Length   :");
    reset_color();
    printf(" %d  Bytes(Size of Packet)\n",ntohs(iph->tot_len));

    magenta_color();
    printf("Identification    :");
    reset_color();
    printf(" %d\n",ntohs(iph->id));

    magenta_color();
    printf("TTL      : ");
    reset_color();
    printf("%d\n",(unsigned int)iph->ttl);

    magenta_color();
    printf("Protocol : ");
    reset_color();
    printf("%d\n",(unsigned int)iph->protocol);

    magenta_color();
    printf("Checksum : ");
    reset_color();
    printf("%d\n",ntohs(iph->check));
    
    magenta_color();
    printf("Source IP        : ");
    reset_color();
    printf("%s\n" , inet_ntoa(source.sin_addr) );

    magenta_color();
    printf("Destination IP   : ");
    printf("%s\n" , inet_ntoa(dest.sin_addr));
}


void print_tcp_packet(const u_char * Buffer, int Size)
{
    unsigned short iphdrlen;
     
    struct iphdr *iph = (struct iphdr *)( Buffer  + sizeof(struct ethhdr) );
    iphdrlen = iph->ihl*4;
     
    struct tcphdr *tcph=(struct tcphdr*)(Buffer + iphdrlen + sizeof(struct ethhdr));
             
    int header_size =  sizeof(struct ethhdr) + iphdrlen + tcph->doff*4;

    red_color();
    printf("\n\n***********************TCP Packet*************************\n");
    reset_color();
        
    print_ip_header(Buffer,Size);
         
    printf("\n");
    printf("TCP Header\n");

    magenta_word("Source Port      : ");
    printf("%u\n",ntohs(tcph->source));

    magenta_word("Destination Port : ");
    printf("%u\n",ntohs(tcph->dest));

    magenta_word("Sequence Number    : ");
    printf("%u\n",ntohl(tcph->seq));

    magenta_word("Acknowledge Number : ");
    printf("%u\n",ntohl(tcph->ack_seq));

    magenta_word("Header Length      : ");
    printf("%d DWORDS or %d BYTES\n" ,(unsigned int)tcph->doff,(unsigned int)tcph->doff*4);

    magenta_word("Urgent Flag          : ");
    printf("%d\n",(unsigned int)tcph->urg);


    magenta_word("Acknowledgement Flag : ");
    printf("%d\n",(unsigned int)tcph->ack);


    magenta_word("Push Flag            : ");
    printf("%d\n",(unsigned int)tcph->psh);

    magenta_word("Reset Flag           : ");
    printf("%d\n",(unsigned int)tcph->rst);

    magenta_word("Synchronise Flag     : ");
    printf("%d\n",(unsigned int)tcph->syn);

    magenta_word("Finish Flag          : ");
    printf("%d\n",(unsigned int)tcph->fin);

    magenta_word("Window         : ");
    printf("%d\n",ntohs(tcph->window));

    magenta_word("Checksum       : ");
    printf("%d\n",ntohs(tcph->check));

    magenta_word("Urgent Pointer : ");
    printf("%d\n",tcph->urg_ptr);

    printf("\n");
    // printf("                        DATA Dump                         ");
    // printf("\n");
         
    // printf("IP Header\n");
    // PrintData(Buffer,iphdrlen);
         
    // printf("TCP Header\n");
    // PrintData(Buffer+iphdrlen,tcph->doff*4);
    red_color();  
    printf("Data Payload\n"); 
    reset_color();

    PrintData(Buffer + header_size , Size - header_size );

    red_color();             
    printf("\n###############################################################");
    reset_color();
}
 
void print_udp_packet(const u_char *Buffer , int Size)
{
     
    unsigned short iphdrlen;
     
    struct iphdr *iph = (struct iphdr *)(Buffer +  sizeof(struct ethhdr));
    iphdrlen = iph->ihl*4;
     
    struct udphdr *udph = (struct udphdr*)(Buffer + iphdrlen  + sizeof(struct ethhdr));
     
    int header_size =  sizeof(struct ethhdr) + iphdrlen + sizeof udph;
    
    red_color();
    printf("\n\n***********************UDP Packet*************************\n");
    reset_color();

    print_ip_header(Buffer,Size);           
    
    red_color();
    printf("\nUDP Header\n");
    reset_color();

    magenta_word("Source Port      : ");
    printf("%d\n" , ntohs(udph->source));

    magenta_word("Destination Port : ");
    printf("%d\n" , ntohs(udph->dest));

    magenta_word("UDP Length       : ");
    printf("%d\n" , ntohs(udph->len));

    magenta_word("UDP Checksum     : ");
    printf("%d\n" , ntohs(udph->check));
     
    // printf("\n");
    // printf("IP Header\n");
    // PrintData(Buffer , iphdrlen);
         
    // printf("UDP Header\n");
    // PrintData(Buffer+iphdrlen , sizeof udph);
    
    red_color();
    printf("Data Payload\n");  
    reset_color();  
     
    //Move the pointer ahead and reduce the size of string
    PrintData(Buffer + header_size , Size - header_size);
    
    red_color();
    printf("\n###############################################################");
    reset_color();
}
 
void print_icmp_packet(const u_char * Buffer , int Size)
{
    unsigned short iphdrlen;
     
    struct iphdr *iph = (struct iphdr *)(Buffer  + sizeof(struct ethhdr));
    iphdrlen = iph->ihl * 4;
     
    struct icmphdr *icmph = (struct icmphdr *)(Buffer + iphdrlen  + sizeof(struct ethhdr));
     
    int header_size =  sizeof(struct ethhdr) + iphdrlen + sizeof icmph;

    red_color(); 
    printf("\n\n***********************ICMP Packet*************************\n"); 
    reset_color();

    print_ip_header(Buffer , Size);
             
    printf("\n");
    
    red_color();
    printf("ICMP Header\n");
    reset_color();

    magenta_word("Type : ");
    printf("%d",(unsigned int)(icmph->type));
             
    if((unsigned int)(icmph->type) == 11)
    {
        red_color();
        printf("  (TTL Expired)\n");
        reset_color();
    }
    else if((unsigned int)(icmph->type) == ICMP_ECHOREPLY)
    {
        green_color();
        printf("  (ICMP Echo Reply)\n");
        reset_color();
    }
    magenta_word("Code : ");
    printf("%d\n",(unsigned int)(icmph->code));

    magenta_word("Checksum : ");
    printf("%d\n",ntohs(icmph->checksum));

    //printf("ID       : %d\n",ntohs(icmph->id));
    //printf("Sequence : %d\n",ntohs(icmph->sequence));
    printf("\n");
 
    // printf("IP Header\n");
    // PrintData(Buffer,iphdrlen);
         
    // printf("UDP Header\n");
    // PrintData(Buffer + iphdrlen , sizeof icmph);
    
    red_color();
    printf("Data Payload\n");    
    reset_color();
     
    //Move the pointer ahead and reduce the size of string
    PrintData(Buffer + header_size , (Size - header_size) );
    
    red_color();
    printf("\n################################################################");
    reset_color();
}

void print_other_packets(const u_char *data, int Size){
    red_color();
    printf("\n\n***********************Other Packet*************************\n"); 
    reset_color();

    print_ethernet_header(data,Size);
    red_color(); 
    
    reset_color();
    PrintData(data,Size);
    red_color();
    printf("\n#################################################################");
    reset_color();
}
void PrintData (const u_char * data , int Size)
{
   //u_char *ptr=(u_char *)data;
 //  const char* S1 = reinterpret_cast<const char*>(data);
  // fprintf(logfile,"%s\n",S1);
    int i , j;
    for(i=0 ; i < Size ; i++)
    {
        if( i!=0 && i%16==0)   //if one line of hex printing is complete...
        {
            printf("         ");
            for(j=i-16 ; j<i ; j++)
            {
                if(data[j]>=32 && data[j]<=128)
                    printf("%c",(unsigned char)data[j]); //if its a number or alphabet
                 
                else printf("."); //otherwise print a dot
            }
            printf("\n");
        } 
         
        if(i%16==0) printf("   ");
            printf(" %02X",(unsigned int)data[i]);
                 
        if( i==Size-1)  //print the last spaces
        {
            for(j=0;j<15-i%16;j++) 
            {
              printf("   "); //extra spaces
            }
             
            printf("         ");
             
            for(j=i-i%16 ; j<=i ; j++)
            {
                if(data[j]>=32 && data[j]<=128) 
                {
                  printf("%c",(unsigned char)data[j]);
                }
                else
                {
                  printf(".");
                }
            }
             
            printf( "\n" );
        }
    }
}

