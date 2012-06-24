/*!
************************************************************************
[udp-broadcast-relay for Android]
@file         udp_bcast_relay.cpp
@brief        broadcast helper application
              Forwards UDP broadcast packets to all local
              interfaces as though they originated from sender
@note   usage: command [-d] packet-id portno [portno ...]

Copyright (c) 2012 Naohisa Fukuoka

Based upon:
udp-broadcast-relay ; Relays UDP broadcasts to other networks, forging
    the sender address.
  Copyright (c) 2003 Joachim Breitner <mail@joachim-breitner.de>
udp_broadcast_fw ; Forwards UDP broadcast packets to all local
    interfaces as though they originated from sender
  Copyright (C) 2002  Nathan O'Sullivan

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.
************************************************************************
Thanks:
Arny <cs6171@scitsc.wlv.ac.uk>
- public domain UDP spoofing code
http://www.netfor2.com/ip.htm
- IP/UDP packet formatting info
*/

#undef LOG_TAG
#define LOG_TAG "udp_bcast_relay"
#define HAVE_SYS_UIO_H 1

#include <stdlib.h>
#include <stdio.h>
#include <errno.h>

#include <sys/socket.h>
#include <arpa/inet.h>

#ifdef __cplusplus
#include <utils/Log.h>	// android logger util.
#endif


#define DPRINT  		if (debug) LOGW
#define MAXRCVPORT		(8)
#define IPHEADER_LEN	(20)
#define UDPHEADER_LEN	(8)
#define HEADER_LEN		(IPHEADER_LEN + UDPHEADER_LEN)
#define TTL_ID_OFFSET	(64)
 

/* send socket info */
static struct {
	struct sockaddr_in addr;
	int raw_socket;		// for spoofing them (type RAW)
} snd;

/* list of recive socket info */
static struct {
	int			ifindex;
	struct sockaddr_in addr;
	int			fd;		// for receiving broadcast packets (type UDP)
	u_int16_t	port;
	char		rsv[2];	// padding
} rcv[MAXRCVPORT];

/* 1. IP Header Format
 0                   1                   2                   3   
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|Version|  IHL  |Type of Service|          Total Length         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|         Identification        |Flags|      Fragment Offset    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Time to Live |    Protocol   |         Header Checksum       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       Source Address                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Destination Address                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Options                    |    Padding    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/
/* Where we forge our packets */
static u_char gram[4096]=
{
	0x45,	0x00,	0x00,	0x26,
	0x84,	0x21,	0x00,	0x00,
	0xFF,	0x11,	0,	0,
	0,	0,	0,	0,
	0,	0,	0,	0,
	0x00,	0x00,	0x00,	0x00,
	0x00,	0x12,	0x00,	0x00,
	'U','D','P','r','e','l','a','y','0','0'
};

//using namespace android;//

void usage( char *prg) {
	fprintf(stderr, "usage: %s [-d] packet-id portno [portno ...]\n",prg);
	fprintf(stderr,	"     : -d :enables Debugging\n");
	fprintf(stderr,	"     : packet-id :1-99\n");
}

int main(int argc,char **argv)
{
	/* Debugging, forking, other settings */
	int debug=0, forking=0;
	
	struct timeval	tv;
	fd_set		fds;
	int			max_fd;
	u_char		id;
	u_char		ttl;
	int			rcv_num=0;	// num of recive socket info
	int			err;


	/* Address broadcast packet was sent from */
	struct sockaddr_in	rcv_addr;
	
	/* Incoming message read via rcvsmsg */
	struct msghdr		rcv_msg;
	struct iovec		iov;
	u_char				pkt_infos[16384];
	struct in_pktinfo	*pktinfo;

	/* various variables */
	int		x=1;
	int		len;
	
	struct cmsghdr		*cmsg;
	int		*ttlptr=NULL;
	int		rcv_ifindex = 0;
	char	buf[256];

	iov.iov_base			= gram+ HEADER_LEN; 
	iov.iov_len				= 4006 - HEADER_LEN - 1;
	
	rcv_msg.msg_name		= &rcv_addr;
	rcv_msg.msg_namelen 	= sizeof(rcv_addr);
	rcv_msg.msg_iov			= &iov;
	rcv_msg.msg_iovlen		= 1;
	rcv_msg.msg_control 	= pkt_infos;
	rcv_msg.msg_controllen	= sizeof(pkt_infos);
	
	/* parsing the args */
	if(argc < 3 || argc > 3 + MAXRCVPORT )
	{
		usage(*argv);
		exit(1);
	};
	
	if ((debug = (strcmp(argv[1],"-d") == 0)))
	{
		argc--;
		argv++;
		LOGW ("Debugging Mode enabled\n");
	} else {
		forking = 1;
	};

	if ((id = atoi(argv[1])) == 0)
	{
		LOGE ("ID argument not valid\n");
		exit(1);
	}
	if (id < 1 || id > 99)
	{
		LOGE ("ID argument %i not between 1 and 99\n",id);
		exit(1);
	}

	ttl = id+TTL_ID_OFFSET;
	gram[8] = ttl;
	/* The id is used to detect packets we just sent, and is stored in the "ttl" field,
	 * which is not used with broadcast packets. Beware when using this with
	 * non-broadcast-packets */
	argc--;
	argv++;


	for (rcv_num=0; argc>1; argc--, argv++)
	{
		struct sockaddr_in	addr;
		int					fd;
		u_int16_t			port;

		if ((port = atoi(argv[1])) == 0)
		{
			LOGE ("Port argument not valid\n");
			exit(1);
		}
		
		/* Create our broadcast receiving socket */
		if((fd=socket(AF_INET,SOCK_DGRAM,IPPROTO_UDP)) < 0)
	  	{
	  		LOGE("socket %d %s\n", errno, strerror(errno));
	  		exit(1);
	  	};
	
		x = 1;
		if(setsockopt(fd, SOL_SOCKET, SO_BROADCAST, (char*) &x, sizeof(int))<0){
			LOGE("SO_BROADCAST on rcv %d %s\n", errno, strerror(errno));
			exit(1);
		};
		if(setsockopt(fd, SOL_IP, IP_RECVTTL, (char*) &x, sizeof(int))<0){
			LOGE("IP_RECVTTL on rcv %d %s\n", errno, strerror(errno));
			exit(1);
		};
		if(setsockopt(fd, SOL_IP, IP_PKTINFO, (char*) &x, sizeof(int))<0){
			LOGE("IP_PKTINFO on rcv  %d %s\n", errno, strerror(errno));
			exit(1);
		};
	
		/* We bind it to broadcast addr on the given port */
		addr.sin_family = AF_INET;
		addr.sin_port = htons(port);
		addr.sin_addr.s_addr = INADDR_ANY;
	
		if ( bind (fd, (struct sockaddr *)&addr, sizeof(struct sockaddr_in) ) < 0 )
		{
			LOGE("bind  %d %s\n", errno, strerror(errno));
			LOGE("A program is already bound to the broadcast address for the given port\n");
			exit(1);
		}

		/* add one value to recive list */
		rcv[rcv_num].addr		= addr;
		rcv[rcv_num].ifindex	= 0;
		rcv[rcv_num].fd			= fd;
		rcv[rcv_num].port		= port;

		LOGW("listen. fd=%d -- %s:%d\n", rcv[rcv_num].fd,
								inet_ntoa(rcv[rcv_num].addr.sin_addr),
								rcv[rcv_num].port);
		rcv_num++;
	}

	if (rcv_num < 1) {
		usage(*argv);
		exit(1);
	}

	/* Create dest sending socket. */
	/* Set up a one raw socket per interface for sending our packets through */
	if((snd.raw_socket = socket(AF_INET,SOCK_RAW,IPPROTO_RAW)) < 0)
	{
		LOGE("socket %d %s\n", errno, strerror(errno));
		exit(1);
	};
	x=1;
	if (setsockopt(snd.raw_socket,SOL_SOCKET,SO_BROADCAST,(char*)&x,sizeof(x))<0)
	{
		LOGE("setsockopt SO_BROADCAST %d %s\n", errno, strerror(errno));
		exit(1);
	};
	/* Enable IP header stuff on the raw socket */
	#ifdef IP_HDRINCL
	x=1;
	if (setsockopt(snd.raw_socket,IPPROTO_IP,IP_HDRINCL,(char*)&x,sizeof(x))<0)
	{
		LOGE("setsockopt IP_HDRINCL %d %s\n", errno, strerror(errno));
		exit(1);
	};
	#else
	#error IP_HDRINCL support is required
	#endif

 	/* Fork to background */
	if (! debug) {
		if (forking && fork()) {
	    	exit(0);
		}

    	fclose(stdin);
    	fclose(stdout);
    	fclose(stderr);
	}

	LOGW("Done Initializing. (listen ports total %i)\n", rcv_num);

	for (;;) /* endless loop */
	{
		int i;

		tv.tv_sec = 5;	// :-) heart beat
		tv.tv_usec = 0;
		max_fd=0;
		FD_ZERO(&fds);
		for (i=0; i<rcv_num; i++) {
			FD_SET(rcv[i].fd, &fds);
			max_fd = (rcv[i].fd > max_fd ? rcv[i].fd : max_fd);
		}

		/* blocking read fds */
		err = select(max_fd+1, &fds, NULL, NULL, &tv);
		if ( err > 0 ) {

			for (i=0; i<rcv_num; i++) {

				if (! FD_ISSET(rcv[i].fd, &fds) ) {
					continue;
				}

				/* Overwrite recv address */
				rcv_addr = rcv[i].addr;
		
				DPRINT("recv packet...fd=%d -- %s:%d\n", rcv[i].fd, inet_ntoa(rcv[i].addr.sin_addr), rcv[i].port); 
		
				/* Receive a broadcast packet */
				len = recvmsg(rcv[i].fd, &rcv_msg, 0);
				if (len <= 0) continue;	/* ignore broken packets */
		
				/* Find the ttl and the receiving interface */
				pktinfo=NULL;
				ttlptr=NULL;
				if (rcv_msg.msg_controllen>0) {
				  for (cmsg=CMSG_FIRSTHDR(&rcv_msg);cmsg;cmsg=CMSG_NXTHDR(&rcv_msg,cmsg)) {
				    if (cmsg->cmsg_type==IP_TTL) {
				      ttlptr = (int *)CMSG_DATA(cmsg);
				    }
				    if (cmsg->cmsg_type==IP_PKTINFO) {
				      pktinfo=((struct in_pktinfo *)CMSG_DATA(cmsg));
				    }
				  }
				}
		
				if (pktinfo == NULL) {
					DPRINT ("No pktinfo received.\n");
					continue;
				}
				rcv_ifindex=pktinfo->ipi_ifindex;
		
				if (ttlptr == NULL) {
					LOGE("TTL not found on incoming packet %d %s\n", errno, strerror(errno));
					continue;
				}
				if (*ttlptr == ttl) {
					DPRINT ("Drop. got local packet (TTL %i) on interface %i\n",*ttlptr,rcv_ifindex);
					continue;
				}
		
				gram[HEADER_LEN + len] =0;
				DPRINT("Got remote packet:\n");
				DPRINT("In  :\t\t%s\n",inet_ntoa(pktinfo->ipi_spec_dst));
				DPRINT("Dest:\t\t%s\n",inet_ntoa(pktinfo->ipi_addr));
				DPRINT("TTL-ID:\t\t%i\n",*ttlptr);
				DPRINT("Interface:\t%i\n",rcv_ifindex);
				strcpy(buf, inet_ntoa(rcv_addr.sin_addr));
				DPRINT("From:\t\t%s:%d\n",buf,rcv_addr.sin_port);
		
				/* drop unicast packet */
				if (pktinfo->ipi_spec_dst.s_addr == pktinfo->ipi_addr.s_addr) {
					DPRINT ("Drop. got unicast packet on interface %i\n", rcv_ifindex);
					continue;
				}
			
				/* copy sender's details into our datagram as the source addr */	
				bcopy(&(rcv_addr.sin_addr.s_addr),(gram+12),4);
			  	*(u_short*)(gram+20)=(u_short)rcv_addr.sin_port;
		
				/* set the length of the packet */
				*(u_short*)(gram+24)=htons(8 + len);
				*(u_short*)(gram+2)=htons(28+len);
		
				/* packet send. */
				{
		
					/* Set dstination addr ip */
					bcopy(&(pktinfo->ipi_addr.s_addr),(gram+16),4);	
		
					/* Set dest port to that was provided on command line */
					*(u_short*)(gram+22)=(u_short)htons(rcv[i].port);
		
					snd.addr.sin_family = AF_INET;
					snd.addr.sin_port = htons(rcv[i].port);
					snd.addr.sin_addr = pktinfo->ipi_addr;
		
					DPRINT ("if:%i %s:%d --> %s:%d\n",
						rcv_ifindex, /* source */
						buf,
						rcv_addr.sin_port,
						inet_ntoa(snd.addr.sin_addr), /* dst ip */
						ntohs(*(u_short*)(gram+22))); /* dst port */
						
					/* Send the packet */
					if (sendto(snd.raw_socket,
							&gram,
							28+len,0,
							(struct sockaddr*)&snd.addr,sizeof(struct sockaddr))  < 0) {
						LOGE("sendto %d %s\n", errno, strerror(errno));
					}
				}
			}

		} else if ( err == 0 ) {
			// time out
			//DPRINT("select timeout.\n");
		} else {
			// select error
			LOGE("select %d %s\n", errno, strerror(errno));
		}
	}
}
