// node_ecies_wrapper.h
#ifndef ECIESWRAPPER_H
#define ECIESWRAPPER_H

#include <nan.h>
#include "ecc.h"
#include "hex.h"

namespace node_ecies {

class ECIESWrapper : public node::ObjectWrap {
	public:
		static ECIES_privkey_t privateKey;
		static ECIES_pubkey_t publicKey;
		static void Init(v8::Local<v8::Object> exports);

	private:
		explicit ECIESWrapper(double value = 0);
		~ECIESWrapper();

	static void New(const Nan::FunctionCallbackInfo<v8::Value>& args);
	static void GenerateKeys(const Nan::FunctionCallbackInfo<v8::Value>& args);
	static void GetKeys(const Nan::FunctionCallbackInfo<v8::Value>& args);
	static void SetClientPublicKey(const Nan::FunctionCallbackInfo<v8::Value>& args);
	static void SetPrivateKey(const Nan::FunctionCallbackInfo<v8::Value>& args);
	static void Encrypt(const Nan::FunctionCallbackInfo<v8::Value>& args);
	static void Decrypt(const Nan::FunctionCallbackInfo<v8::Value>& args);

	// Test code
	static void GetGazePoint(const Nan::FunctionCallbackInfo<v8::Value>& args);
	static void PlusOne(const Nan::FunctionCallbackInfo<v8::Value>& args);
	static Nan::Persistent<v8::Function> constructor;
	double value_;
};

}  // namespace node_ecies

#endif
