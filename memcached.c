#include <event2/listener.h>
#include <event2/bufferevent.h>
#include <event2/buffer.h>

#include <arpa/inet.h>

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>

#include "protocol_binary.h"
#include "jenkins_hash.h"

#define HASH_BITS 16
#define HASH_MASK ((1 << HASH_BITS)-1)

typedef struct conn_t{

   struct bufferevent *bev;

   char   *rbuf;   /** buffer to read commands into */
   int    rsize;   /** total allocated size of rbuf */

   char   *wbuf;
   int    wsize;

   //binary protocol
   protocol_binary_request_header* req_header;
   protocol_binary_response_header* res_header;
   
}conn;


typedef struct kvitem_t{
     int keylen;
     int datalen;
     char *data;
     struct kvitem_t *next;
}kvitem;

static kvitem** hashtable;

void hashtable_init()
{
	hashtable = calloc(1<<HASH_BITS, sizeof(void *));
}

void hashtable_insert_item(kvitem *item, int hashval)
{
	item->next = (kvitem*) hashtable[hashval & HASH_MASK];
	hashtable[hashval & HASH_MASK] = item;
}

kvitem* hashtable_get_item(char* key, int keylen, int hashval)
{
 	kvitem *found_item = NULL;
	kvitem *item = hashtable[hashval & HASH_MASK];
 	while (item) {
		if ((item->keylen == keylen) && (memcmp(key, item->data, keylen)==0))	{
			found_item = item;
			break;
		}
		item = item->next;
	}
	return found_item;
}

kvitem* create_kvitem(char* keyvalue, int keylen, int vlen)
{
	kvitem* newitem = calloc(1, sizeof(kvitem));
	newitem->keylen = keylen;
	newitem->datalen = vlen;
	newitem->data = calloc(keylen+vlen,sizeof(char));
	memcpy(newitem->data , keyvalue, keylen+vlen);
	newitem->next = NULL;
	return newitem;
}

static void
print_helper(char* code , int len)
{
   int i;
   for (i=0;i<len;i++){
	fprintf(stderr, "%c", code[i]);
   }
}

static void 
process_cmd(conn *c, struct bufferevent *bev)
{
        struct evbuffer *input = bufferevent_get_input(bev);
	c->rbuf = (char *)malloc((size_t)c->rsize);
	evbuffer_remove(input, c->rbuf, c->rsize);

	c->req_header  = (protocol_binary_request_header*)c->rbuf;


	fprintf(stderr, " Read binary protocol data:");
	int ii;
	for (ii = 0; ii < c->rsize ; ++ii) {
	//for (ii = 0; ii < sizeof(c->req_header->bytes) ; ++ii) {
		if (ii % 4 == 0) {
			fprintf(stderr, "\n   ");
		}
		fprintf(stderr, " 0x%02x",c->req_header->bytes[ii]);
	}
	fprintf(stderr, "\n");

        c->req_header->request.keylen = ntohs(c->req_header->request.keylen);
        c->req_header->request.bodylen = ntohl(c->req_header->request.bodylen);

	char* key;
	int klen;
	char *value;
	int vlen;

	klen = c->req_header->request.keylen;
	fprintf(stderr, "klen = %d ",klen);
	key = c->rbuf + sizeof(c->req_header->bytes) + c->req_header->request.extlen;

	vlen = c->req_header->request.bodylen - klen - c->req_header->request.extlen;
	fprintf(stderr, "bodylen=%d ; extlen=%d; vlen = %d \n ",c->req_header->request.bodylen,  c->req_header->request.extlen, vlen);
	value = key + klen;

	char* keyforhash = malloc(klen+1);
	memcpy(keyforhash,key,klen);
	*(keyforhash+klen+1) = 0;
	uint32_t hv = jenkins_hash(keyforhash, klen);
	free(keyforhash);

	if (c->req_header->request.opcode == PROTOCOL_BINARY_CMD_SET) {
		fprintf(stderr, "SET ");
                print_helper(key , klen); 
		fprintf(stderr, " :  ");
                print_helper(value , vlen); 
		fprintf(stderr, "\n ");
		fprintf(stderr, "set item hv=%d\n ",(hv & HASH_MASK));

		//setitem
		kvitem* it = hashtable_get_item(key, klen, hv);
		if (it){ //key already exists. replace value
			fprintf(stderr, "key already exists. replace value \n ");
			if (vlen < it->datalen){
				char *newvalue = it->data+klen;
				memcpy(newvalue, value,vlen);
				it->datalen = vlen;
			}else{
				char *newkeyvalue = malloc(klen+vlen);
				memcpy(newkeyvalue, it->data ,klen);
				memcpy(newkeyvalue+klen, value ,vlen);
				it->datalen = vlen;
			 	free(it->data);
				it->data = newkeyvalue;	
			}
		}else{
			//create new item to store
			fprintf(stderr, "insert new item \n ");
			kvitem* newit = create_kvitem( key, klen, vlen);
			hashtable_insert_item(newit, hv);
		}
		//prepare reply
		c->wsize = sizeof(protocol_binary_response_header);
		c->wbuf = calloc(c->wsize,sizeof(char));
		c->res_header = (protocol_binary_response_header*) c->wbuf;
		c->res_header->response.status = (uint16_t)htons(0);	

	} else if (c->req_header->request.opcode == PROTOCOL_BINARY_CMD_GET) {
		fprintf(stderr, "GET ");
                print_helper(key , klen); 
		fprintf(stderr, "\n ");
		fprintf(stderr, "search  item hv=%d\n ",(hv & HASH_MASK));

		//getitem 
		kvitem* it = hashtable_get_item(key, klen, hv);
		if (it){
			fprintf(stderr, "found item ");
			key = it->data;
			value = it->data + it->keylen;
			print_helper(key , it->keylen); 
			fprintf(stderr, " :  ");
			print_helper(value , it->datalen); 
			fprintf(stderr, "\n ");
		}else{
			fprintf(stderr, "not found item \n");
		}
		//prepare reply
		if(it){
			uint32_t ext_hdr = htonl(0x00000000);
			int ext_hdr_len = sizeof(ext_hdr);
			c->wsize = sizeof(protocol_binary_response_header)+it->datalen+ext_hdr_len;
			c->wbuf = calloc(c->wsize,sizeof(char));
			c->res_header = (protocol_binary_response_header*) c->wbuf;
			c->res_header->response.status = (uint16_t)htons(0);	
			c->res_header->response.keylen = (uint16_t)htons(0);
			c->res_header->response.extlen = (uint8_t)ext_hdr_len;
			c->res_header->response.bodylen = (uint32_t)htonl(it->datalen+ext_hdr_len);
			//c->res_header->response.cas = htonll(1);
			memcpy(c->wbuf+sizeof(protocol_binary_response_header) , &ext_hdr, ext_hdr_len);
			memcpy(c->wbuf+sizeof(protocol_binary_response_header)+ext_hdr_len , value , it->datalen);
		}else{
			char err[] = "NotFound";
			int err_len = sizeof(err);
			c->wsize = sizeof(protocol_binary_response_header)+err_len;
			c->wbuf = calloc(c->wsize,sizeof(char));
			c->res_header = (protocol_binary_response_header*) c->wbuf;
			c->res_header->response.status = (uint16_t)htons(1);	
			c->res_header->response.extlen = (uint8_t)0;
			c->res_header->response.bodylen = (uint32_t)htonl(err_len);
			memcpy(c->wbuf+sizeof(protocol_binary_response_header) , err , err_len);
		}
	} 

	c->res_header->response.magic = (uint8_t)PROTOCOL_BINARY_RES;
	c->res_header->response.opcode = c->req_header->request.opcode;
	c->res_header->response.datatype = (uint8_t)PROTOCOL_BINARY_RAW_BYTES;
	c->res_header->response.opaque = c->req_header->request.opaque;
	//write response

	fprintf(stderr, " Write binary protocol data:");
        for (ii = 0; ii < c->wsize ; ++ii) {
        //for (ii = 0; ii < sizeof(c->req_header->bytes) ; ++ii) {
                if (ii % 4 == 0) {
                        fprintf(stderr, "\n   ");
                }
                fprintf(stderr, " 0x%02x",c->res_header->bytes[ii]);
        }
        fprintf(stderr, "\n");
	struct evbuffer *output = bufferevent_get_output(bev);
 	evbuffer_add(output, c->wbuf , c->wsize);	
}

static void
echo_read_cb(struct bufferevent *bev, void *ctx)
{
        conn *c = (conn*) ctx;
        /* This callback is invoked when there is data to read on bev. */
        struct evbuffer *input = bufferevent_get_input(bev);
        c->rsize = evbuffer_get_length(input);
	if (c->rsize < sizeof(protocol_binary_request_header)) {
		fprintf(stderr, "need more data on read");
		/* need more data! */
		return ;
	}
       
        process_cmd(c,bev);
}

static void
echo_event_cb(struct bufferevent *bev, short events, void *ctx)
{
        if (events & BEV_EVENT_ERROR)
                perror("Error from bufferevent");
        if (events & (BEV_EVENT_EOF | BEV_EVENT_ERROR)) {
                bufferevent_free(bev);
        }
        //todo : free conn
}

static void
accept_conn_cb(struct evconnlistener *listener,
    evutil_socket_t fd, struct sockaddr *address, int socklen,
    void *ctx)
{
        /* We got a new connection! Set up a bufferevent for it. */
        struct event_base *base = evconnlistener_get_base(listener);
        struct bufferevent *bev = bufferevent_socket_new(
                base, fd, BEV_OPT_CLOSE_ON_FREE);

        conn *c = malloc(sizeof(conn));

        bufferevent_setcb(bev, echo_read_cb, NULL, echo_event_cb, c);

        bufferevent_enable(bev, EV_READ|EV_WRITE);
}

static void
accept_error_cb(struct evconnlistener *listener, void *ctx)
{
        struct event_base *base = evconnlistener_get_base(listener);
        int err = EVUTIL_SOCKET_ERROR();
        fprintf(stderr, "Got an error %d (%s) on the listener. "
                "Shutting down.\n", err, evutil_socket_error_to_string(err));

        event_base_loopexit(base, NULL);
}

int
main(int argc, char **argv)
{
        struct event_base *base;
        struct evconnlistener *listener;
        struct sockaddr_in sin;

        int port = 9876;

        if (argc > 1) {
                port = atoi(argv[1]);
        }
        if (port<=0 || port>65535) {
                puts("Invalid port");
                return 1;
        }

        base = event_base_new();
        if (!base) {
                puts("Couldn't open event base");
                return 1;
        }
	hashtable_init();

        /* Clear the sockaddr before using it, in case there are extra
         * platform-specific fields that can mess us up. */
        memset(&sin, 0, sizeof(sin));
        /* This is an INET address */
        sin.sin_family = AF_INET;
        /* Listen on 0.0.0.0 */
        sin.sin_addr.s_addr = htonl(0);
        /* Listen on the given port. */
        sin.sin_port = htons(port);

        listener = evconnlistener_new_bind(base, accept_conn_cb, NULL,
            LEV_OPT_CLOSE_ON_FREE|LEV_OPT_REUSEABLE, -1,
            (struct sockaddr*)&sin, sizeof(sin));
        if (!listener) {
                perror("Couldn't create listener");
                return 1;
        }
        evconnlistener_set_error_cb(listener, accept_error_cb);

        event_base_dispatch(base);
        return 0;
}
