/*
 * Copyright (C) 2011, 2012, 2013 Citrix Systems
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the project nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE PROJECT AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE PROJECT OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifndef __LIB_TURN_MSG_CPP__
#define __LIB_TURN_MSG_CPP__

#include "ns_turn_ioaddr.h"
#include "ns_turn_msg.h"

#include <string>

namespace turn {

class StunAttr;

/**
 * Exception "end of buffer"
 */
class EndOfStunMsgException {
public:
	EndOfStunMsgException() {}
	virtual ~EndOfStunMsgException() {}
};

/**
 * Exception "wrong format of StunAttr"
 */
class WrongStunAttrFormatException {
public:
	WrongStunAttrFormatException() {}
	virtual ~WrongStunAttrFormatException() {}
};

/**
 * Exception "wrong format of StunBuffer"
 */
class WrongStunBufferFormatException {
public:
	WrongStunBufferFormatException() {}
	virtual ~WrongStunBufferFormatException() {}
};

/**
 * Iterator class for attributes
 */
class StunAttrIterator {
public:
	/**
	 * Iterator constructor: creates iterator on raw messagebuffer.
	 */
	StunAttrIterator(uint8_t *buf, size_t sz) :
		_buf(buf), _sz(sz)  {
		if(!stun_is_command_message_str(_buf, _sz)) {
			throw WrongStunBufferFormatException();
		}
		_sar = stun_attr_get_first_str(_buf, _sz);
	}

	/**
	 * Iterator constructor: create iterator over message.
	 */
	template<class T>
	StunAttrIterator(T &msg) :
		_buf(msg.getRawBuffer()), _sz(msg.getSize())  {
		if(!stun_is_command_message_str(_buf, _sz)) {
			throw WrongStunBufferFormatException();
		}
		_sar = stun_attr_get_first_str(_buf, _sz);
	}

	/**
	 * Iterator constructor: creates iterator over raw buffer, starting from first
	 * location of an attribute of particular type.
	 */
	StunAttrIterator(uint8_t *buf, size_t sz, uint16_t attr_type) :
			_buf(buf), _sz(sz)  {
		if(!stun_is_command_message_str(_buf, _sz)) {
			throw WrongStunBufferFormatException();
		}
		_sar = stun_attr_get_first_by_type_str(_buf, _sz, attr_type);
	}

	/**
	 * Iterator constructor: creates iterator over message, starting from first
	 * location of an attribute of particular type.
	 */
	template<class T>
	StunAttrIterator(T &msg, uint16_t attr_type) :
			_buf(msg.getRawBuffer()), _sz(msg.getSize())  {
		if(!stun_is_command_message_str(_buf, _sz)) {
			throw WrongStunBufferFormatException();
		}
		_sar = stun_attr_get_first_by_type_str(_buf, _sz, attr_type);
	}

	/**
	 * Moves iterator to next attribute location
	 */
	void next() {
		if(!_sar) {
			throw EndOfStunMsgException();
		}
		_sar = stun_attr_get_next_str(_buf,_sz,_sar);
	}

	/**
	 * Is the iterator finished
	 */
	bool eof() const {
		return (!_sar);
	}

	/**
	 * Is the iterator at an address attribute
	 */
	bool isAddr() const {
		return stun_attr_is_addr(_sar);
	}

	/**
	 * Return address family attribute value (if the iterator at the "address family" attribute.
	 */
	int getAddressFamily() const {
		return stun_get_requested_address_family(_sar);
	}

	/**
	 * Get attribute type
	 */
	int getType() const {
		return stun_attr_get_type(_sar);
	}

	/**
	 * Destructor
	 */
	virtual ~StunAttrIterator() {}

	/**
	 * Return raw memroy field of the attribute value.
	 * If the attribute value length is zero (0), then return NULL.
	 */
	const uint8_t *getRawBuffer(size_t &sz) const {
		int len = stun_attr_get_len(_sar);
		if(len<0)
			throw WrongStunAttrFormatException();
		sz = (size_t)len;
		const uint8_t *value = stun_attr_get_value(_sar);
		return value;
	}
	friend class StunAttr;
private:
	uint8_t *_buf;
	size_t _sz;
	stun_attr_ref _sar;
};

/**
 * Root class of all STUN attributes.
 * Can be also used for a generic attribute object.
 */
class StunAttr {
public:
	/**
	 * Empty constructor
	 */
	StunAttr() : _attr_type(0), _value(0), _sz(0) {}

	/**
	 * Constructs attribute from iterator
	 */
	StunAttr(const StunAttrIterator &iter) {
		if(iter.eof()) {
			throw EndOfStunMsgException();
		}
		size_t sz = 0;
		const uint8_t *ptr = iter.getRawBuffer(sz);
		if(sz>=0xFFFF)
			throw WrongStunAttrFormatException();
		int at = iter.getType();
		if(at<0)
			throw WrongStunAttrFormatException();
		_attr_type = (uint16_t)at;
		_sz = sz;
		_value=(uint8_t*)malloc(_sz);
		if(ptr)
			bcopy(ptr,_value,_sz);
	}

	/**
	 * Destructor
	 */
	virtual ~StunAttr() {
		if(_value)
			free(_value);
	}

	/**
	 * Return raw data representation of the attribute
	 */
	const uint8_t *getRawValue(size_t &sz) const {
		sz=_sz;
		return _value;
	}

	/**
	 * Set raw data value
	 */
	void setRawValue(uint8_t *value, size_t sz) {
		if(sz>0xFFFF)
			throw WrongStunAttrFormatException();
		if(_value)
			free(_value);
		_sz = sz;
		_value=(uint8_t*)malloc(_sz);
		if(value)
			bcopy(value,_value,_sz);
	}

	/**
	 * Get attribute type
	 */
	uint16_t getType() const {
		return _attr_type;
	}

	/**
	 * Set attribute type
	 */
	void setType(uint16_t at) {
		_attr_type = at;
	}

	/**
	 * Add attribute to a message
	 */
	template<class T>
	int addToMsg(T &msg) {
		if(!_attr_type)
			throw WrongStunAttrFormatException();
		uint8_t *buffer = msg.getRawBuffer();
		if(buffer) {
			size_t sz = msg.getSize();
			if(addToBuffer(buffer, sz)<0) {
				throw WrongStunBufferFormatException();
			}
			msg.setSize(sz);
			return 0;
		}
		throw WrongStunBufferFormatException();
	}
protected:

	/**
	 * Virtual function member to add attribute to a raw buffer
	 */
	virtual int addToBuffer(uint8_t *buffer, size_t &sz) {
		if(buffer) {
			if(!_value)
				throw WrongStunAttrFormatException();
			if(stun_attr_add_str(buffer, &sz, _attr_type, _value, _sz)<0) {
				throw WrongStunBufferFormatException();
			}
			return 0;
		}
		throw WrongStunBufferFormatException();
	}

	/**
	 * Get low-level iterator object
	 */
	static stun_attr_ref getSar(const StunAttrIterator &iter) {
		return iter._sar;
	}
private:
	uint16_t _attr_type;
	uint8_t *_value;
	size_t _sz;
};

/**
 * Channel number attribute class
 */
class StunAttrChannelNumber : public StunAttr {
public:
	StunAttrChannelNumber() : _cn(0) {
		setType(STUN_ATTRIBUTE_CHANNEL_NUMBER);
	}
	StunAttrChannelNumber(const StunAttrIterator &iter) :
		StunAttr(iter) {

		if(iter.eof())
			throw EndOfStunMsgException();
		_cn = stun_attr_get_channel_number(getSar(iter));
		if(!_cn)
			throw WrongStunAttrFormatException();
	}
	virtual ~StunAttrChannelNumber() {}
	uint16_t getChannelNumber() const {
		return _cn;
	}
	void setChannelNumber(uint16_t cn) {
		_cn = cn;
	}
protected:
	virtual int addToBuffer(uint8_t *buffer, size_t &sz) {
		return stun_attr_add_channel_number_str(buffer,&sz,_cn);
	}
private:
	uint16_t _cn;
};

/**
 * Even port attribute class
 */
class StunAttrEvenPort : public StunAttr {
public:
	StunAttrEvenPort() : _ep(0) {
		setType(STUN_ATTRIBUTE_EVEN_PORT);
	}
	StunAttrEvenPort(const StunAttrIterator &iter) :
		StunAttr(iter) {

		if(iter.eof())
			throw EndOfStunMsgException();
		_ep = stun_attr_get_even_port(getSar(iter));
	}
	virtual ~StunAttrEvenPort() {}
	uint8_t getEvenPort() const {
		return _ep;
	}
	void setEvenPort(uint8_t ep) {
		_ep = ep;
	}
protected:
	virtual int addToBuffer(uint8_t *buffer, size_t &sz) {
		return stun_attr_add_str(buffer, &sz, STUN_ATTRIBUTE_EVEN_PORT, &_ep, 1);
	}
private:
	uint8_t _ep;
};

/**
 * Reservation token attribute class
 */
class StunAttrReservationToken : public StunAttr {
public:
	StunAttrReservationToken() : _rt(0) {
		setType(STUN_ATTRIBUTE_RESERVATION_TOKEN);
	}
	StunAttrReservationToken(const StunAttrIterator &iter) :
		StunAttr(iter) {

		if(iter.eof())
			throw EndOfStunMsgException();
		_rt = stun_attr_get_reservation_token_value(getSar(iter));
	}
	virtual ~StunAttrReservationToken() {}
	uint64_t getReservationToken() const {
		return _rt;
	}
	void setReservationToken(uint64_t rt) {
		_rt = rt;
	}
protected:
	virtual int addToBuffer(uint8_t *buffer, size_t &sz) {
		uint64_t reservation_token = ioa_ntoh64(_rt);
		return stun_attr_add_str(buffer, &sz, STUN_ATTRIBUTE_RESERVATION_TOKEN, (uint8_t*) (&reservation_token), 8);
	}
private:
	uint64_t _rt;
};

/**
 * This attribute class is used for all address attributes
 */
class StunAttrAddr : public StunAttr {
public:
	StunAttrAddr(uint16_t attr_type = 0) {
		addr_set_any(&_addr);
		setType(attr_type);
	}
	StunAttrAddr(const StunAttrIterator &iter) :
		StunAttr(iter) {

		if(iter.eof())
			throw EndOfStunMsgException();
		size_t sz = 0;
		const uint8_t *buf = iter.getRawBuffer(sz);
		if(stun_attr_get_addr_str(buf,sz,getSar(iter),&_addr,NULL)<0) {
			throw WrongStunAttrFormatException();
		}
	}
	virtual ~StunAttrAddr() {}
	void getAddr(ioa_addr &addr) const {
		addr_cpy(&addr,&_addr);
	}
	void setAddr(ioa_addr &addr) {
		addr_cpy(&_addr,&addr);
	}
protected:
	virtual int addToBuffer(uint8_t *buffer, size_t &sz) {
		return stun_attr_add_addr_str(buffer, &sz, getType(), &_addr);
	}
private:
	ioa_addr _addr;
};

/**
 * Change Request attribute class
 */
class StunAttrChangeRequest : public StunAttr {
public:
	StunAttrChangeRequest() : _changeIp(0), _changePort(0) {
		setType(STUN_ATTRIBUTE_CHANGE_REQUEST);
	}
	StunAttrChangeRequest(const StunAttrIterator &iter) :
		StunAttr(iter) {

		if(iter.eof())
			throw EndOfStunMsgException();

		if(stun_attr_get_change_request_str(getSar(iter), &_changeIp, &_changePort)<0) {
			throw WrongStunAttrFormatException();
		}
	}
	virtual ~StunAttrChangeRequest() {}
	bool getChangeIp() const {
		return _changeIp;
	}
	void setChangeIp(bool ci) {
		if(ci)
			_changeIp = 1;
		else
			_changeIp = 0;
	}
	bool getChangePort() const {
		return _changePort;
	}
	void setChangePort(bool cp) {
		if(cp)
			_changePort = 1;
		else
			_changePort = 0;
	}
protected:
	virtual int addToBuffer(uint8_t *buffer, size_t &sz) {
		return stun_attr_add_change_request_str(buffer, &sz, _changeIp, _changePort);
	}
private:
	int _changeIp;
	int _changePort;
};

/**
 * Change Request attribute class
 */
class StunAttrResponsePort : public StunAttr {
public:
	StunAttrResponsePort() : _rp(0) {
		setType(STUN_ATTRIBUTE_RESPONSE_PORT);
	}
	StunAttrResponsePort(const StunAttrIterator &iter) :
		StunAttr(iter) {

		if(iter.eof())
			throw EndOfStunMsgException();

		int rp = stun_attr_get_response_port_str(getSar(iter));
		if(rp<0) {
			throw WrongStunAttrFormatException();
		}
		_rp = (uint16_t)rp;
	}
	virtual ~StunAttrResponsePort() {}
	uint16_t getResponsePort() const {
		return _rp;
	}
	void setResponsePort(uint16_t p) {
		_rp = p;
	}
protected:
	virtual int addToBuffer(uint8_t *buffer, size_t &sz) {
		return stun_attr_add_response_port_str(buffer, &sz, _rp);
	}
private:
	uint16_t _rp;
};

/**
 * Padding attribute class
 */
class StunAttrPadding : public StunAttr {
public:
	StunAttrPadding() : _p(0) {
		setType(STUN_ATTRIBUTE_PADDING);
	}
	StunAttrPadding(const StunAttrIterator &iter) :
		StunAttr(iter) {

		if(iter.eof())
			throw EndOfStunMsgException();

		int p = stun_attr_get_padding_len_str(getSar(iter));
		if(p<0) {
			throw WrongStunAttrFormatException();
		}
		_p = (uint16_t)p;
	}
	virtual ~StunAttrPadding() {}
	uint16_t getPadding() const {
		return _p;
	}
	/**
	 * Set length of padding
	 */
	void setPadding(uint16_t p) {
		_p = p;
	}
protected:
	virtual int addToBuffer(uint8_t *buffer, size_t &sz) {
		return stun_attr_add_padding_str(buffer, &sz, _p);
	}
private:
	uint16_t _p;
};

/**
 * Generic "STUN Message" class, base class for all messages
 */
class StunMsg {
public:
	/**
	 * Empty constructor
	 */
	StunMsg() {
		_allocated_sz = 0xFFFF;
		_buffer = (uint8_t*)malloc(_allocated_sz);
		_deallocate = true;
		_sz = 0;
		_constructed = 0;
	}

	/**
	 * Construct message over raw buffer.
	 * Parameter "construct" is true if the buffer is initialized.
	 */
	StunMsg(uint8_t *buffer, size_t total_sz, size_t sz, bool constructed) :
		_buffer(buffer), _deallocate(false), _allocated_sz(total_sz),
		_sz(sz), _constructed(constructed) {}

	/**
	 * Destructor
	 */
	virtual ~StunMsg() {
		if(_deallocate && _buffer) {
			free(_buffer);
		}
	}

	/**
	 * Initialize buffer
	 */
	void construct() {
		constructBuffer();
	}

	/**
	 * Checks if the message is properly constructed
	 */
	bool isValid() {
		return check();
	}

	/**
	 * get raw buffer
	 */
	uint8_t *getRawBuffer() {
		return _buffer;
	}

	/**
	 * Get message size in the buffer (message can be mnuch smaller than the whole buffer)
	 */
	size_t getSize() const {
		return _sz;
	}

	/**
	 * Set message size
	 */
	void setSize(size_t sz) {
		if(sz>_allocated_sz)
			throw WrongStunBufferFormatException();
		_sz = sz;
	}

	/**
	 * Check if the raw buffer is a TURN "command" (request, response or indication).
	 */
	static bool isCommand(uint8_t *buffer, size_t sz) {
		return stun_is_command_message_str(buffer, sz);
	}

	/**
	 * Check if the current message object is a "command" (request, response, or indication).
	 */
	bool isCommand() const {
		return stun_is_command_message_str(_buffer, _sz);
	}

	static bool isIndication(uint8_t *buffer, size_t sz) {
		return stun_is_indication_str(buffer, sz);
	}

	static bool isRequest(uint8_t *buffer, size_t sz) {
		return stun_is_request_str(buffer, sz);
	}

	static bool isSuccessResponse(uint8_t *buffer, size_t sz) {
		return stun_is_success_response_str(buffer, sz);
	}

	static bool isErrorResponse(uint8_t *buffer, size_t sz,
					int &err_code, uint8_t *err_msg, size_t err_msg_size) {
		return stun_is_error_response_str(buffer, sz, &err_code, err_msg, err_msg_size);
	}

	/**
	 * Check if the raw buffer is a challenge response (the one with 401 error and realm and nonce values).
	 */
	static bool isChallengeResponse(const uint8_t* buf, size_t sz,
					int &err_code, uint8_t *err_msg, size_t err_msg_size,
					uint8_t *realm, uint8_t *nonce,
					uint8_t *server_name, int *oauth) {
		return stun_is_challenge_response_str(buf, sz, &err_code, err_msg, err_msg_size, realm, nonce, server_name, oauth);
	}

	/**
	 * Check if the message is a channel message
	 */
	static bool isChannel(uint8_t *buffer, size_t sz) {
		return is_channel_msg_str(buffer, sz);
	}

	/**
	 * Check if the fingerprint is present.
	 */
	static bool isFingerprintPresent(uint8_t *buffer, size_t sz) {
		if(!stun_is_command_message_str(buffer,sz))
			return false;
		stun_attr_ref sar = stun_attr_get_first_by_type_str(buffer, sz, STUN_ATTRIBUTE_FINGERPRINT);
		if(!sar)
			return false;

		return true;
	}

	/**
	 * Check the fingerprint
	 */
	static bool checkFingerprint(uint8_t *buffer, size_t sz) {
		return stun_is_command_message_full_check_str(buffer, sz, 1, NULL);
	}

	/**
	 * Add attribute to the message
	 */
	int addAttr(StunAttr &attr) {
		return attr.addToMsg(*this);
	}

	/**
	 * Get transaction ID
	 */
	virtual stun_tid getTid() const {
		if(!_constructed || !isCommand())
			throw WrongStunBufferFormatException();
		stun_tid tid;
		stun_tid_from_message_str(_buffer,_sz,&tid);
		return tid;
	}

	/**
	 * Set transaction ID
	 */
	virtual void setTid(stun_tid &tid) {
		if(!_constructed || !isCommand())
			throw WrongStunBufferFormatException();
		stun_tid_message_cpy(_buffer, &tid);
	}

	/**
	 * Add fingerprint to the message
	 */
	void addFingerprint() {
		if(!_constructed || !isCommand())
			throw WrongStunBufferFormatException();
		stun_attr_add_fingerprint_str(_buffer,&_sz);
	}

	/**
	 * Check message integrity, in secure communications.
	 */
	bool checkMessageIntegrity(turn_credential_type ct, std::string &uname, std::string &realm, std::string &upwd) const {
		if(!_constructed || !isCommand())
			throw WrongStunBufferFormatException();
		uint8_t *suname=(uint8_t*)strdup(uname.c_str());
		uint8_t *srealm=(uint8_t*)strdup(realm.c_str());
		uint8_t *supwd=(uint8_t*)strdup(upwd.c_str());
		SHATYPE sht = SHATYPE_SHA1;
		bool ret = (0< stun_check_message_integrity_str(ct,_buffer, _sz, suname, srealm, supwd, sht));
		free(suname);
		free(srealm);
		free(supwd);
		return ret;
	}

	/**
	 * Adds long-term message integrity data to the message.
	 */
	void addLTMessageIntegrity(std::string &uname, std::string &realm, std::string &upwd, std::string &nonce) {

		if(!_constructed || !isCommand())
			throw WrongStunBufferFormatException();

		uint8_t *suname=(uint8_t*)strdup(uname.c_str());
		uint8_t *srealm=(uint8_t*)strdup(realm.c_str());
		uint8_t *supwd=(uint8_t*)strdup(upwd.c_str());
		uint8_t *snonce=(uint8_t*)strdup(nonce.c_str());

		stun_attr_add_integrity_by_user_str(_buffer, &_sz, suname, srealm, supwd, snonce, SHATYPE_SHA1);

		free(suname);
		free(srealm);
		free(supwd);
		free(snonce);
	}

	/**
	 * Adds short-term message integrity data to the message.
	 */
	void addSTMessageIntegrity(std::string &uname, std::string &upwd) {

		if(!_constructed || !isCommand())
			throw WrongStunBufferFormatException();

		uint8_t *suname=(uint8_t*)strdup(uname.c_str());
		uint8_t *supwd=(uint8_t*)strdup(upwd.c_str());

		stun_attr_add_integrity_by_user_short_term_str(_buffer, &_sz, suname, supwd, SHATYPE_SHA1);

		free(suname);
		free(supwd);
	}

protected:
	virtual void constructBuffer() = 0;
	virtual bool check() = 0;
protected:
	uint8_t *_buffer;
	bool _deallocate;
	size_t _allocated_sz;
	size_t _sz;
	bool _constructed;
};

/**
 * Class that represents the "request" flavor of STUN/TURN messages.
 */
class StunMsgRequest : public StunMsg {
public:
	StunMsgRequest(uint16_t method) : _method(method) {};
	StunMsgRequest(uint8_t *buffer, size_t total_sz, size_t sz, bool constructed) :
			StunMsg(buffer,total_sz,sz,constructed),_method(0) {

		if(constructed) {
			if(!stun_is_request_str(buffer,sz)) {
				throw WrongStunBufferFormatException();
			}
			_method = stun_get_method_str(buffer,sz);
		}
	}
	virtual ~StunMsgRequest() {}

	/**
	 * Get request method
	 */
	uint16_t getMethod() const {
		return _method;
	}

	/**
	 * Set method
	 */
	void setMethod(uint16_t method) {
		_method = method;
	}

	/**
	 * Construct binding request
	 */
	void constructBindingRequest() {
		stun_set_binding_request_str(_buffer, &_sz);
	}

	bool isBindingRequest() const {
		return stun_is_binding_request_str(_buffer,_sz,0);
	}

	/**
	 * Construct allocate request
	 */
	void constructAllocateRequest(uint32_t lifetime, int af4, int af6, uint8_t transport, int mobile, const char* rt, int ep) {
		stun_set_allocate_request_str(_buffer, &_sz, lifetime, af4, af6, transport, mobile, rt, ep);
	}

	/**
	 * Construct channel bind request
	 */
	void constructChannelBindRequest(const ioa_addr &peer_addr, uint16_t channel_number) {
		stun_set_channel_bind_request_str(_buffer, &_sz,
					&peer_addr, channel_number);
	}

protected:
	virtual void constructBuffer() {
		stun_init_request_str(_method,_buffer,&_sz);
		_constructed = true;
	}

	virtual bool check() {
		if(!_constructed)
			return false;
		if(!stun_is_request_str(_buffer,_sz)) {
			return false;
		}
		if(_method != stun_get_method_str(_buffer,_sz)) {
			return false;
		}
		return true;
	}

private:
	uint16_t _method;
};

/**
 * Class for STUN/TURN responses
 */
class StunMsgResponse : public StunMsg {
public:
	StunMsgResponse(uint16_t method, stun_tid &tid) : _method(method), _err(0), _reason(""), _tid(tid) {};
	StunMsgResponse(uint16_t method, int error_code, std::string reason, stun_tid &tid) :
		_method(method), _err(error_code), _reason(reason), _tid(tid) {

	};
	StunMsgResponse(uint8_t *buffer, size_t total_sz, size_t sz, bool constructed) :
			StunMsg(buffer,total_sz,sz,constructed),_method(0),_err(0),_reason("") {

		if(constructed) {
			if(!stun_is_success_response_str(buffer,sz)) {
				uint8_t errtxt[0xFFFF];
				if(!stun_is_error_response_str(buffer,sz,&_err,errtxt,sizeof(errtxt))) {
					throw WrongStunBufferFormatException();
				}
				_reason = (char*)errtxt;
			}
			_method = stun_get_method_str(buffer,sz);
			stun_tid_from_message_str(_buffer,_sz,&_tid);
		}
	}

	uint16_t getMethod() const {
		return _method;
	}

	void setMethod(uint16_t method) {
		_method = method;
	}

	/**
	 * Get error code
	 */
	int getError() const {
		return _err;
	}

	/**
	 * Set error code
	 */
	void setError(int err) {
		_err = err;
	}

	/**
	 * Get error message
	 */
	std::string getReason() const {
		return _reason;
	}

	/**
	 * Set error message
	 */
	void setReason(std::string reason) {
		_reason = reason;
	}

	/**
	 * Set transaction ID
	 */
	void setTid(stun_tid &tid) {
		_tid = tid;
	}

	/**
	 * Get transaction ID
	 */
	virtual stun_tid getTid() const {
		return _tid;
	}

	/**
	 * Check if this is a challenge response, and return realm and nonce
	 */
	bool isChallenge(std::string &realm, std::string &nonce) const {
		bool ret = false;
		if(_constructed) {
			int err_code;
			uint8_t err_msg[1025];
			size_t err_msg_size=sizeof(err_msg);
			uint8_t srealm[0xFFFF];
			uint8_t snonce[0xFFFF];
			ret = stun_is_challenge_response_str(_buffer, _sz, &err_code, err_msg, err_msg_size, srealm, snonce, NULL, NULL);
			if(ret) {
				realm = (char*)srealm;
				nonce = (char*)snonce;
			}
		}
		return ret;
	}

	bool isChallenge() const {
		std::string realm, nonce;
		return isChallenge(realm, nonce);
	}

	/**
	 * Check if this is a success response
	 */
	bool isSuccess() const {
		return (_err == 0);
	}

	/**
	 * Construct binding response
	 */
	void constructBindingResponse(stun_tid &tid,
				const ioa_addr &reflexive_addr, int error_code,
				const uint8_t *reason) {

		stun_set_binding_response_str(_buffer, &_sz, &tid,
					&reflexive_addr, error_code,
					reason, 0 , 0);
	}

	bool isBindingResponse() const {
		return stun_is_binding_response_str(_buffer,_sz);
	}

	/**
	 * Construct allocate response
	 */
	void constructAllocateResponse(stun_tid &tid,
					   const ioa_addr &relayed_addr1,
					   const ioa_addr &relayed_addr2,
					   const ioa_addr &reflexive_addr,
					   uint32_t lifetime, int error_code, const uint8_t *reason,
					   uint64_t reservation_token, char *mobile_id) {

		stun_set_allocate_response_str(_buffer, &_sz, &tid,
						   &relayed_addr1, &relayed_addr2,
						   &reflexive_addr,
						   lifetime, STUN_DEFAULT_MAX_ALLOCATE_LIFETIME, error_code, reason,
						   reservation_token, mobile_id);
	}

	/**
	 * Construct channel bind response
	 */
	void constructChannelBindResponse(stun_tid &tid, int error_code, const uint8_t *reason) {
		stun_set_channel_bind_response_str(_buffer, &_sz, &tid, error_code, reason);
	}

protected:
	virtual void constructBuffer() {
		if(_err) {
			stun_init_error_response_str(_method, _buffer, &_sz, _err, (const uint8_t*)_reason.c_str(), &_tid);
		} else {
			stun_init_success_response_str(_method, _buffer, &_sz, &_tid);
		}
		_constructed = true;
	}

	virtual bool check() {
		if(!_constructed)
			return false;
		if(!stun_is_success_response_str(_buffer,_sz)) {
			uint8_t errtxt[0xFFFF];
			int cerr=0;
			if(!stun_is_error_response_str(_buffer,_sz,&cerr,errtxt,sizeof(errtxt))) {
				throw WrongStunBufferFormatException();
			}
			if(cerr != _err) {
				throw WrongStunBufferFormatException();
			}
		}
		if(_method != stun_get_method_str(_buffer,_sz)) {
			return false;
		}
		return true;
	}

private:
	uint16_t _method;
	int _err;
	std::string _reason;
	stun_tid _tid;
};

/**
 * Class for STUN/TURN indications
 */
class StunMsgIndication : public StunMsg {
public:
	StunMsgIndication(uint16_t method) : _method(method) {};
	StunMsgIndication(uint8_t *buffer, size_t total_sz, size_t sz, bool constructed) :
			StunMsg(buffer,total_sz,sz,constructed),_method(0) {

		if(constructed) {
			if(!stun_is_indication_str(buffer,sz)) {
				throw WrongStunBufferFormatException();
			}
			_method = stun_get_method_str(buffer,sz);
		}
	}
	virtual ~StunMsgIndication() {}

	uint16_t getMethod() const {
		return _method;
	}

	void setMethod(uint16_t method) {
		_method = method;
	}

protected:
	virtual void constructBuffer() {
		stun_init_indication_str(_method,_buffer,&_sz);
		_constructed = true;
	}

	virtual bool check() {
		if(!_constructed)
			return false;
		if(!stun_is_indication_str(_buffer,_sz)) {
			return false;
		}
		if(_method != stun_get_method_str(_buffer,_sz)) {
			return false;
		}
		return true;
	}

private:
	uint16_t _method;
};

/**
 * Channel message
 */
class StunMsgChannel : public StunMsg {
public:
	StunMsgChannel(uint16_t cn, int length) : _cn(cn), _len(length) {};
	StunMsgChannel(uint8_t *buffer, size_t total_sz, size_t sz, bool constructed) :
			StunMsg(buffer,total_sz,sz,constructed),_cn(0) {

		if(constructed) {
			if(!stun_is_channel_message_str(buffer,&_sz,&_cn,0)) {
				throw WrongStunBufferFormatException();
			}
			if(_sz>0xFFFF || _sz<4)
				throw WrongStunBufferFormatException();

			_len = _sz-4;
		} else {
			if(total_sz>0xFFFF || total_sz<4)
				throw WrongStunBufferFormatException();

			_len = 0;
		}
	}
	virtual ~StunMsgChannel() {}

	uint16_t getChannelNumber() const {
		return _cn;
	}

	void setChannelNumber(uint16_t cn) {
		_cn = cn;
	}

	/**
	 * Get length of message itself (excluding the 4 channel number bytes)
	 */
	size_t getLength() const {
		return _len;
	}

	/**
	 * Set length of message itself (excluding the 4 channel number bytes)
	 */
	void setLength(size_t len) {
		_len = len;
	}

protected:
	virtual void constructBuffer() {
		stun_init_channel_message_str(_cn,_buffer,&_sz,(int)_len,0);
		_constructed = true;
	}

	virtual bool check() {
		if(!_constructed)
			return false;
		uint16_t cn = 0;
		if(!stun_is_channel_message_str(_buffer,&_sz,&cn,0)) {
			return false;
		}
		if(_cn != cn) {
			return false;
		}
		return true;
	}

private:
	uint16_t _cn;
	size_t _len;
};

};
/* namespace */

#endif
/* __LIB_TURN_MSG_CPP__ */
