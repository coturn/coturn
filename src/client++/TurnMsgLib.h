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
	StunAttrIterator(u08bits *buf, size_t sz) throw (WrongStunBufferFormatException) :
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
	StunAttrIterator(T &msg) throw (WrongStunBufferFormatException) :
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
	StunAttrIterator(u08bits *buf, size_t sz, u16bits attr_type) throw (WrongStunBufferFormatException) :
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
	StunAttrIterator(T &msg, u16bits attr_type) throw (WrongStunBufferFormatException) :
			_buf(msg.getRawBuffer()), _sz(msg.getSize())  {
		if(!stun_is_command_message_str(_buf, _sz)) {
			throw WrongStunBufferFormatException();
		}
		_sar = stun_attr_get_first_by_type_str(_buf, _sz, attr_type);
	}

	/**
	 * Moves iterator to next attribute location
	 */
	void next() throw(EndOfStunMsgException) {
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
	const u08bits *getRawBuffer(size_t &sz) const throw(WrongStunAttrFormatException) {
		int len = stun_attr_get_len(_sar);
		if(len<0)
			throw WrongStunAttrFormatException();
		sz = (size_t)len;
		const u08bits *value = stun_attr_get_value(_sar);
		return value;
	}
	friend class StunAttr;
private:
	u08bits *_buf;
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
	StunAttr(const StunAttrIterator &iter) throw(WrongStunAttrFormatException, EndOfStunMsgException) {
		if(iter.eof()) {
			throw EndOfStunMsgException();
		}
		size_t sz = 0;
		const u08bits *ptr = iter.getRawBuffer(sz);
		if(sz>=0xFFFF)
			throw WrongStunAttrFormatException();
		int at = iter.getType();
		if(at<0)
			throw WrongStunAttrFormatException();
		_attr_type = (u16bits)at;
		_sz = sz;
		_value=(u08bits*)turn_malloc(_sz);
		if(ptr)
			ns_bcopy(ptr,_value,_sz);
	}

	/**
	 * Destructor
	 */
	virtual ~StunAttr() {
		if(_value)
			turn_free(_value,_sz);
	}

	/**
	 * Return raw data representation of the attribute
	 */
	const u08bits *getRawValue(size_t &sz) const {
		sz=_sz;
		return _value;
	}

	/**
	 * Set raw data value
	 */
	void setRawValue(u08bits *value, size_t sz) throw(WrongStunAttrFormatException) {
		if(sz>0xFFFF)
			throw WrongStunAttrFormatException();
		if(_value)
			turn_free(_value,_sz);
		_sz = sz;
		_value=(u08bits*)turn_malloc(_sz);
		if(value)
			ns_bcopy(value,_value,_sz);
	}

	/**
	 * Get attribute type
	 */
	u16bits getType() const {
		return _attr_type;
	}

	/**
	 * Set attribute type
	 */
	void setType(u16bits at) {
		_attr_type = at;
	}

	/**
	 * Add attribute to a message
	 */
	template<class T>
	int addToMsg(T &msg) throw(WrongStunAttrFormatException, WrongStunBufferFormatException) {
		if(!_attr_type)
			throw WrongStunAttrFormatException();
		u08bits *buffer = msg.getRawBuffer();
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
	virtual int addToBuffer(u08bits *buffer, size_t &sz) throw(WrongStunAttrFormatException, WrongStunBufferFormatException) {
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
	u16bits _attr_type;
	u08bits *_value;
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
	StunAttrChannelNumber(const StunAttrIterator &iter)
		throw(WrongStunAttrFormatException, EndOfStunMsgException) :
		StunAttr(iter) {

		if(iter.eof())
			throw EndOfStunMsgException();
		_cn = stun_attr_get_channel_number(getSar(iter));
		if(!_cn)
			throw WrongStunAttrFormatException();
	}
	virtual ~StunAttrChannelNumber() {}
	u16bits getChannelNumber() const {
		return _cn;
	}
	void setChannelNumber(u16bits cn) {
		_cn = cn;
	}
protected:
	virtual int addToBuffer(u08bits *buffer, size_t &sz) throw(WrongStunAttrFormatException, WrongStunBufferFormatException) {
		return stun_attr_add_channel_number_str(buffer,&sz,_cn);
	}
private:
	u16bits _cn;
};

/**
 * Even port attribute class
 */
class StunAttrEvenPort : public StunAttr {
public:
	StunAttrEvenPort() : _ep(0) {
		setType(STUN_ATTRIBUTE_EVEN_PORT);
	}
	StunAttrEvenPort(const StunAttrIterator &iter)
		throw(WrongStunAttrFormatException, EndOfStunMsgException) :
		StunAttr(iter) {

		if(iter.eof())
			throw EndOfStunMsgException();
		_ep = stun_attr_get_even_port(getSar(iter));
	}
	virtual ~StunAttrEvenPort() {}
	u08bits getEvenPort() const {
		return _ep;
	}
	void setEvenPort(u08bits ep) {
		_ep = ep;
	}
protected:
	virtual int addToBuffer(u08bits *buffer, size_t &sz) throw(WrongStunAttrFormatException, WrongStunBufferFormatException) {
		return stun_attr_add_str(buffer, &sz, STUN_ATTRIBUTE_EVEN_PORT, &_ep, 1);
	}
private:
	u08bits _ep;
};

/**
 * Reservation token attribute class
 */
class StunAttrReservationToken : public StunAttr {
public:
	StunAttrReservationToken() : _rt(0) {
		setType(STUN_ATTRIBUTE_RESERVATION_TOKEN);
	}
	StunAttrReservationToken(const StunAttrIterator &iter)
		throw(WrongStunAttrFormatException, EndOfStunMsgException) :
		StunAttr(iter) {

		if(iter.eof())
			throw EndOfStunMsgException();
		_rt = stun_attr_get_reservation_token_value(getSar(iter));
	}
	virtual ~StunAttrReservationToken() {}
	u64bits getReservationToken() const {
		return _rt;
	}
	void setReservationToken(u64bits rt) {
		_rt = rt;
	}
protected:
	virtual int addToBuffer(u08bits *buffer, size_t &sz) throw(WrongStunAttrFormatException, WrongStunBufferFormatException) {
		uint64_t reservation_token = ioa_ntoh64(_rt);
		return stun_attr_add_str(buffer, &sz, STUN_ATTRIBUTE_RESERVATION_TOKEN, (u08bits*) (&reservation_token), 8);
	}
private:
	u64bits _rt;
};

/**
 * This attribute class is used for all address attributes
 */
class StunAttrAddr : public StunAttr {
public:
	StunAttrAddr(u16bits attr_type = 0) {
		addr_set_any(&_addr);
		setType(attr_type);
	}
	StunAttrAddr(const StunAttrIterator &iter)
		throw(WrongStunAttrFormatException, EndOfStunMsgException) :
		StunAttr(iter) {

		if(iter.eof())
			throw EndOfStunMsgException();
		size_t sz = 0;
		const u08bits *buf = iter.getRawBuffer(sz);
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
	virtual int addToBuffer(u08bits *buffer, size_t &sz) throw(WrongStunAttrFormatException, WrongStunBufferFormatException) {
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
	StunAttrChangeRequest(const StunAttrIterator &iter)
		throw(WrongStunAttrFormatException, EndOfStunMsgException) :
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
	virtual int addToBuffer(u08bits *buffer, size_t &sz) throw(WrongStunAttrFormatException, WrongStunBufferFormatException) {
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
	StunAttrResponsePort(const StunAttrIterator &iter)
		throw(WrongStunAttrFormatException, EndOfStunMsgException) :
		StunAttr(iter) {

		if(iter.eof())
			throw EndOfStunMsgException();

		int rp = stun_attr_get_response_port_str(getSar(iter));
		if(rp<0) {
			throw WrongStunAttrFormatException();
		}
		_rp = (u16bits)rp;
	}
	virtual ~StunAttrResponsePort() {}
	u16bits getResponsePort() const {
		return _rp;
	}
	void setResponsePort(u16bits p) {
		_rp = p;
	}
protected:
	virtual int addToBuffer(u08bits *buffer, size_t &sz) throw(WrongStunAttrFormatException, WrongStunBufferFormatException) {
		return stun_attr_add_response_port_str(buffer, &sz, _rp);
	}
private:
	u16bits _rp;
};

/**
 * Padding attribute class
 */
class StunAttrPadding : public StunAttr {
public:
	StunAttrPadding() : _p(0) {
		setType(STUN_ATTRIBUTE_PADDING);
	}
	StunAttrPadding(const StunAttrIterator &iter)
		throw(WrongStunAttrFormatException, EndOfStunMsgException) :
		StunAttr(iter) {

		if(iter.eof())
			throw EndOfStunMsgException();

		int p = stun_attr_get_padding_len_str(getSar(iter));
		if(p<0) {
			throw WrongStunAttrFormatException();
		}
		_p = (u16bits)p;
	}
	virtual ~StunAttrPadding() {}
	u16bits getPadding() const {
		return _p;
	}
	/**
	 * Set length of padding
	 */
	void setPadding(u16bits p) {
		_p = p;
	}
protected:
	virtual int addToBuffer(u08bits *buffer, size_t &sz) throw(WrongStunAttrFormatException, WrongStunBufferFormatException) {
		return stun_attr_add_padding_str(buffer, &sz, _p);
	}
private:
	u16bits _p;
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
		_buffer = (u08bits*)turn_malloc(_allocated_sz);
		_deallocate = true;
		_sz = 0;
		_constructed = 0;
	}

	/**
	 * Construct message over raw buffer.
	 * Parameter "construct" is true if the buffer is initialized.
	 */
	StunMsg(u08bits *buffer, size_t total_sz, size_t sz, bool constructed) :
		_buffer(buffer), _deallocate(false), _allocated_sz(total_sz),
		_sz(sz), _constructed(constructed) {}

	/**
	 * Destructor
	 */
	virtual ~StunMsg() {
		if(_deallocate && _buffer) {
			turn_free(_buffer, _allocated_sz);
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
	u08bits *getRawBuffer() {
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
	void setSize(size_t sz) throw(WrongStunBufferFormatException) {
		if(sz>_allocated_sz)
			throw WrongStunBufferFormatException();
		_sz = sz;
	}

	/**
	 * Check if the raw buffer is a TURN "command" (request, response or indication).
	 */
	static bool isCommand(u08bits *buffer, size_t sz) {
		return stun_is_command_message_str(buffer, sz);
	}

	/**
	 * Check if the current message object is a "command" (request, response, or indication).
	 */
	bool isCommand() const {
		return stun_is_command_message_str(_buffer, _sz);
	}

	static bool isIndication(u08bits *buffer, size_t sz) {
		return stun_is_indication_str(buffer, sz);
	}

	static bool isRequest(u08bits *buffer, size_t sz) {
		return stun_is_request_str(buffer, sz);
	}

	static bool isSuccessResponse(u08bits *buffer, size_t sz) {
		return stun_is_success_response_str(buffer, sz);
	}

	static bool isErrorResponse(u08bits *buffer, size_t sz,
					int &err_code, u08bits *err_msg, size_t err_msg_size) {
		return stun_is_error_response_str(buffer, sz, &err_code, err_msg, err_msg_size);
	}

	/**
	 * Check if the raw buffer is a challenge response (the one with 401 error and realm and nonce values).
	 */
	static bool isChallengeResponse(const u08bits* buf, size_t sz,
					int &err_code, u08bits *err_msg, size_t err_msg_size,
					u08bits *realm, u08bits *nonce,
					u08bits *server_name, int *oauth) {
		return stun_is_challenge_response_str(buf, sz, &err_code, err_msg, err_msg_size, realm, nonce, server_name, oauth);
	}

	/**
	 * Check if the message is a channel message
	 */
	static bool isChannel(u08bits *buffer, size_t sz) {
		return is_channel_msg_str(buffer, sz);
	}

	/**
	 * Check if the fingerprint is present.
	 */
	static bool isFingerprintPresent(u08bits *buffer, size_t sz) {
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
	static bool checkFingerprint(u08bits *buffer, size_t sz) {
		return stun_is_command_message_full_check_str(buffer, sz, 1, NULL);
	}

	/**
	 * Add attribute to the message
	 */
	int addAttr(StunAttr &attr) throw(WrongStunAttrFormatException, WrongStunBufferFormatException) {
		return attr.addToMsg(*this);
	}

	/**
	 * Get transaction ID
	 */
	virtual stun_tid getTid() const throw(WrongStunBufferFormatException) {
		if(!_constructed || !isCommand())
			throw WrongStunBufferFormatException();
		stun_tid tid;
		stun_tid_from_message_str(_buffer,_sz,&tid);
		return tid;
	}

	/**
	 * Set transaction ID
	 */
	virtual void setTid(stun_tid &tid) throw(WrongStunBufferFormatException) {
		if(!_constructed || !isCommand())
			throw WrongStunBufferFormatException();
		stun_tid_message_cpy(_buffer, &tid);
	}

	/**
	 * Add fingerprint to the message
	 */
	void addFingerprint() throw(WrongStunBufferFormatException) {
		if(!_constructed || !isCommand())
			throw WrongStunBufferFormatException();
		stun_attr_add_fingerprint_str(_buffer,&_sz);
	}

	/**
	 * Check message integrity, in secure communications.
	 */
	bool checkMessageIntegrity(turn_credential_type ct, std::string &uname, std::string &realm, std::string &upwd) const
		throw(WrongStunBufferFormatException) {
		if(!_constructed || !isCommand())
			throw WrongStunBufferFormatException();
		u08bits *suname=(u08bits*)strdup(uname.c_str());
		u08bits *srealm=(u08bits*)strdup(realm.c_str());
		u08bits *supwd=(u08bits*)strdup(upwd.c_str());
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
	void addLTMessageIntegrity(std::string &uname, std::string &realm, std::string &upwd, std::string &nonce)
		throw(WrongStunBufferFormatException) {

		if(!_constructed || !isCommand())
			throw WrongStunBufferFormatException();

		u08bits *suname=(u08bits*)strdup(uname.c_str());
		u08bits *srealm=(u08bits*)strdup(realm.c_str());
		u08bits *supwd=(u08bits*)strdup(upwd.c_str());
		u08bits *snonce=(u08bits*)strdup(nonce.c_str());

		stun_attr_add_integrity_by_user_str(_buffer, &_sz, suname, srealm, supwd, snonce, SHATYPE_SHA1);

		free(suname);
		free(srealm);
		free(supwd);
		free(snonce);
	}

	/**
	 * Adds short-term message integrity data to the message.
	 */
	void addSTMessageIntegrity(std::string &uname, std::string &upwd)
		throw(WrongStunBufferFormatException) {

		if(!_constructed || !isCommand())
			throw WrongStunBufferFormatException();

		u08bits *suname=(u08bits*)strdup(uname.c_str());
		u08bits *supwd=(u08bits*)strdup(upwd.c_str());

		stun_attr_add_integrity_by_user_short_term_str(_buffer, &_sz, suname, supwd, SHATYPE_SHA1);

		free(suname);
		free(supwd);
	}

protected:
	virtual void constructBuffer() = 0;
	virtual bool check() = 0;
protected:
	u08bits *_buffer;
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
	StunMsgRequest(u16bits method) : _method(method) {};
	StunMsgRequest(u08bits *buffer, size_t total_sz, size_t sz, bool constructed)
		throw(WrongStunBufferFormatException) :
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
	u16bits getMethod() const {
		return _method;
	}

	/**
	 * Set method
	 */
	void setMethod(u16bits method) {
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
	void constructAllocateRequest(u32bits lifetime, int af4, int af6, u08bits transport, int mobile, const char* rt, int ep) {
		stun_set_allocate_request_str(_buffer, &_sz, lifetime, af4, af6, transport, mobile, rt, ep);
	}

	/**
	 * Construct channel bind request
	 */
	void constructChannelBindRequest(const ioa_addr &peer_addr, u16bits channel_number) {
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
	u16bits _method;
};

/**
 * Class for STUN/TURN responses
 */
class StunMsgResponse : public StunMsg {
public:
	StunMsgResponse(u16bits method, stun_tid &tid) : _method(method), _err(0), _reason(""), _tid(tid) {};
	StunMsgResponse(u16bits method, int error_code, std::string reason, stun_tid &tid) :
		_method(method), _err(error_code), _reason(reason), _tid(tid) {

	};
	StunMsgResponse(u08bits *buffer, size_t total_sz, size_t sz, bool constructed)
		throw(WrongStunBufferFormatException) :
			StunMsg(buffer,total_sz,sz,constructed),_method(0),_err(0),_reason("") {

		if(constructed) {
			if(!stun_is_success_response_str(buffer,sz)) {
				u08bits errtxt[0xFFFF];
				if(!stun_is_error_response_str(buffer,sz,&_err,errtxt,sizeof(errtxt))) {
					throw WrongStunBufferFormatException();
				}
				_reason = (char*)errtxt;
			}
			_method = stun_get_method_str(buffer,sz);
			stun_tid_from_message_str(_buffer,_sz,&_tid);
		}
	}

	u16bits getMethod() const {
		return _method;
	}

	void setMethod(u16bits method) {
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
	void setTid(stun_tid &tid) throw(WrongStunBufferFormatException) {
		_tid = tid;
	}

	/**
	 * Get transaction ID
	 */
	virtual stun_tid getTid() const throw(WrongStunBufferFormatException) {
		return _tid;
	}

	/**
	 * Check if this is a challenge response, and return realm and nonce
	 */
	bool isChallenge(std::string &realm, std::string &nonce) const {
		bool ret = false;
		if(_constructed) {
			int err_code;
			u08bits err_msg[1025];
			size_t err_msg_size=sizeof(err_msg);
			u08bits srealm[0xFFFF];
			u08bits snonce[0xFFFF];
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
				const u08bits *reason) {

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
					   u32bits lifetime, int error_code, const u08bits *reason,
					   u64bits reservation_token, char *mobile_id) {

		stun_set_allocate_response_str(_buffer, &_sz, &tid,
						   &relayed_addr1, &relayed_addr2,
						   &reflexive_addr,
						   lifetime, error_code, reason,
						   reservation_token, mobile_id);
	}

	/**
	 * Construct channel bind response
	 */
	void constructChannelBindResponse(stun_tid &tid, int error_code, const u08bits *reason) {
		stun_set_channel_bind_response_str(_buffer, &_sz, &tid, error_code, reason);
	}

protected:
	virtual void constructBuffer() {
		if(_err) {
			stun_init_error_response_str(_method, _buffer, &_sz, _err, (const u08bits*)_reason.c_str(), &_tid);
		} else {
			stun_init_success_response_str(_method, _buffer, &_sz, &_tid);
		}
		_constructed = true;
	}

	virtual bool check() {
		if(!_constructed)
			return false;
		if(!stun_is_success_response_str(_buffer,_sz)) {
			u08bits errtxt[0xFFFF];
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
	u16bits _method;
	int _err;
	std::string _reason;
	stun_tid _tid;
};

/**
 * Class for STUN/TURN indications
 */
class StunMsgIndication : public StunMsg {
public:
	StunMsgIndication(u16bits method) : _method(method) {};
	StunMsgIndication(u08bits *buffer, size_t total_sz, size_t sz, bool constructed)
		throw(WrongStunBufferFormatException) :
			StunMsg(buffer,total_sz,sz,constructed),_method(0) {

		if(constructed) {
			if(!stun_is_indication_str(buffer,sz)) {
				throw WrongStunBufferFormatException();
			}
			_method = stun_get_method_str(buffer,sz);
		}
	}
	virtual ~StunMsgIndication() {}

	u16bits getMethod() const {
		return _method;
	}

	void setMethod(u16bits method) {
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
	u16bits _method;
};

/**
 * Channel message
 */
class StunMsgChannel : public StunMsg {
public:
	StunMsgChannel(u16bits cn, int length) : _cn(cn), _len(length) {};
	StunMsgChannel(u08bits *buffer, size_t total_sz, size_t sz, bool constructed)
		throw(WrongStunBufferFormatException) :
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

	u16bits getChannelNumber() const {
		return _cn;
	}

	void setChannelNumber(u16bits cn) {
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
		u16bits cn = 0;
		if(!stun_is_channel_message_str(_buffer,&_sz,&cn,0)) {
			return false;
		}
		if(_cn != cn) {
			return false;
		}
		return true;
	}

private:
	u16bits _cn;
	size_t _len;
};

};
/* namespace */

#endif
/* __LIB_TURN_MSG_CPP__ */
