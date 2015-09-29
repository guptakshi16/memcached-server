
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

#define KEY_MAX_LENGTH 128
#define VAL_MAX_LENGTH 512

#define WBUF_LEN 1024
#define RBUF_LEN 1024

typedef struct conn_t{

	struct bufferevent *bev;

	char   *rbuf; 
	int    rsize;

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
	hashtable = NULL;
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
	kvitem* newitem = NULL;
	newitem = calloc(1, sizeof(kvitem));
	if(newitem){ 
		newitem->keylen = keylen;
		newitem->datalen = vlen;
		newitem->data = calloc(keylen+vlen,sizeof(char));
		if (!newitem->data){
			free(newitem);
			fprintf(stderr, "memory allocation for newitem->data failed");
			newitem = NULL;
			return newitem;
		}
		memcpy(newitem->data , keyvalue, keylen+vlen);
		newitem->next = NULL;
	}
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
free_conn(conn *c, struct bufferevent *bev)
{
	if(c){
		if(c->rbuf)
			free(c->rbuf);
		if (c->wbuf)
			free(c->wbuf);
		if(bev)	
			bufferevent_free(bev);
		free(c);
	}
}

	static void
cmd_reply_error(conn *c, struct bufferevent *bev)
{
	int ii;
	c->wsize = sizeof(protocol_binary_response_header);
	c->wbuf = calloc(c->wsize,sizeof(char));
	if (!c->wbuf){
		fprintf(stderr, "error allocting response: will exit");
		exit(1);
	}
	c->res_header = (protocol_binary_response_header*) c->wbuf;
	c->res_header->response.status = (uint16_t)htons(PROTOCOL_BINARY_RESPONSE_ENOMEM);	
	c->res_header->response.magic = (uint8_t)PROTOCOL_BINARY_RES;
        c->res_header->response.opcode = c->req_header->request.opcode;
        c->res_header->response.datatype = (uint8_t)PROTOCOL_BINARY_RAW_BYTES;
        c->res_header->response.opaque = c->req_header->request.opaque;
	fprintf(stderr, " Write binary protocol data:");
	for (ii = 0; ii < c->wsize ; ++ii) {
		if (ii % 4 == 0) {
			fprintf(stderr, "\n   ");
		}
		fprintf(stderr, " 0x%02x",c->res_header->bytes[ii]);
	}
	fprintf(stderr, "\n");
	struct evbuffer *output = bufferevent_get_output(bev);
	evbuffer_add(output, c->wbuf , c->wsize);	
}

uint32_t generate_hash(char* key, int klen)
{
	uint32_t hv;
	char keyforhash[KEY_MAX_LENGTH];
	memcpy(keyforhash,key,klen);
	*(keyforhash+klen+1) = 0;
	hv = jenkins_hash(keyforhash, klen);
	return hv;
}

	static void 
process_cmd_set(conn *c, struct bufferevent *bev)
{
	//prepare reply
	c->wsize = sizeof(protocol_binary_response_header);
	c->res_header = (protocol_binary_response_header*) c->wbuf;
	c->res_header->response.status = (uint16_t)htons(PROTOCOL_BINARY_RESPONSE_SUCCESS);	
	c->res_header->response.magic = (uint8_t)PROTOCOL_BINARY_RES;
	c->res_header->response.opcode = c->req_header->request.opcode;
	c->res_header->response.datatype = (uint8_t)PROTOCOL_BINARY_RAW_BYTES;
	c->res_header->response.opaque = c->req_header->request.opaque;


	//    MUST have extras.
	//    MUST have key.
	//    MUST have value.

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

	uint32_t hv = generate_hash(key,klen);

	fprintf(stderr, "SET ");
	print_helper(key , klen); 
	fprintf(stderr, " :  ");
	print_helper(value , vlen); 
	fprintf(stderr, "\n ");
	fprintf(stderr, "set item hv=%d\n ",(hv & HASH_MASK));

	kvitem* it = hashtable_get_item(key, klen, hv);

	if (it){ 
		fprintf(stderr, "key already exists. replace value \n ");
		if (vlen < it->datalen){
			char *newvalue = it->data+klen;
			memcpy(newvalue, value,vlen);
			it->datalen = vlen;
		}else{
			char *newkeyvalue = malloc(klen+vlen);
			if (newkeyvalue){
				memcpy(newkeyvalue, it->data ,klen);
				memcpy(newkeyvalue+klen, value ,vlen);
				it->datalen = vlen;
				free(it->data);
				it->data = newkeyvalue;	
			}else{
				fprintf(stderr,"error creating data for newvalue \n");
				c->res_header->response.status = (uint16_t)htons(PROTOCOL_BINARY_RESPONSE_ENOMEM);	
			}
		}
	}else{
		//create new item to store
		fprintf(stderr, "insert new item \n ");
		kvitem* newit = create_kvitem( key, klen, vlen);
		if (newit)
			hashtable_insert_item(newit, hv);
		else{
			fprintf(stderr, "create new item failed\n ");
			c->res_header->response.status = (uint16_t)htons(PROTOCOL_BINARY_RESPONSE_ENOMEM);	
		}
	}

	//write response

	fprintf(stderr, " Write binary protocol data:");
	int ii;
	for (ii = 0; ii < c->wsize ; ++ii) {
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
process_cmd_get(conn *c, struct bufferevent *bev)
{

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
	fprintf(stderr, "GET ");
	print_helper(key , klen); 
	fprintf(stderr, "\n ");

	uint32_t hv = generate_hash(key,klen);
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
		c->res_header = (protocol_binary_response_header*) c->wbuf;
		c->res_header->response.status = (uint16_t)htons(0);	
		c->res_header->response.keylen = (uint16_t)htons(0);
		c->res_header->response.extlen = (uint8_t)ext_hdr_len;
		c->res_header->response.bodylen = (uint32_t)htonl(it->datalen+ext_hdr_len);
		memcpy(c->wbuf+sizeof(protocol_binary_response_header) , &ext_hdr, ext_hdr_len);
		memcpy(c->wbuf+sizeof(protocol_binary_response_header)+ext_hdr_len , value , it->datalen);
	}else{
		char err[] = "NotFound";
		int err_len = sizeof(err);
		c->wsize = sizeof(protocol_binary_response_header)+err_len;
		c->res_header = (protocol_binary_response_header*) c->wbuf;
		c->res_header->response.status = (uint16_t)htons(1);	
		c->res_header->response.extlen = (uint8_t)0;
		c->res_header->response.bodylen = (uint32_t)htonl(err_len);
		memcpy(c->wbuf+sizeof(protocol_binary_response_header) , err , err_len);
	}
	c->res_header->response.magic = (uint8_t)PROTOCOL_BINARY_RES;
	c->res_header->response.opcode = c->req_header->request.opcode;
	c->res_header->response.datatype = (uint8_t)PROTOCOL_BINARY_RAW_BYTES;
	c->res_header->response.opaque = c->req_header->request.opaque;
	//write response

	fprintf(stderr, " Write binary protocol data:");
	int ii;
	for (ii = 0; ii < c->wsize ; ++ii) {
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
process_cmd(conn *c, struct bufferevent *bev)
{
	struct evbuffer *input = bufferevent_get_input(bev);

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

	if (c->req_header->request.opcode == PROTOCOL_BINARY_CMD_SET) {
		process_cmd_set(c,bev);
	} else if (c->req_header->request.opcode == PROTOCOL_BINARY_CMD_GET) {
		process_cmd_get(c,bev);
	} 

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
		//bufferevent_free(bev);
		conn *c = (conn*) ctx;
		free_conn(c,bev);
	}
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

	conn *c = calloc(1, sizeof(conn));
	if (!c){
		fprintf(stderr, "failed to create a new connection");
		return;
	}
	c->wbuf = calloc(WBUF_LEN,sizeof(char));
	c->rbuf = calloc(RBUF_LEN,sizeof(char));
	if (!c->rbuf || !c->wbuf){
		fprintf(stderr, "failed to allocate memory for read/write bufs");
		return;
	}

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
		fprintf(stderr,"Invalid port %d",port);
		return 1;
	}

	base = event_base_new();
	if (!base) {
		fprintf(stderr,"Couldn't open event base");
		return 1;
	}
	hashtable_init();
	if(!hashtable){
		fprintf(stderr, "Memory allocation failed for global hashtable");
		return 1;
	}


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
		fprintf(stderr,"Couldn't create listener");
		return 1;
	}
	evconnlistener_set_error_cb(listener, accept_error_cb);

	event_base_dispatch(base);
	return 0;
}
