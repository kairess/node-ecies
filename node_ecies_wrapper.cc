// node_ecies_wrapper.cc
#include "node_ecies_wrapper.h"

namespace node_ecies {

Nan::Persistent<v8::Function> ECIESWrapper::constructor;

ECIES_privkey_t ECIESWrapper::privateKey = {0};
ECIES_pubkey_t ECIESWrapper::publicKey = {{0},{0}};

ECIESWrapper::ECIESWrapper(double value) : value_(value) {
}

ECIESWrapper::~ECIESWrapper() {
}

// Object initiator
void ECIESWrapper::Init(v8::Local<v8::Object> exports) {
  Nan::HandleScope scope;

  // Prepare constructor template
  v8::Local<v8::FunctionTemplate> tpl = Nan::New<v8::FunctionTemplate>(New);
  tpl->SetClassName(Nan::New("ECIESWrapper").ToLocalChecked());
  tpl->InstanceTemplate()->SetInternalFieldCount(1);

  // Prototype
  Nan::SetPrototypeMethod(tpl, "generateKeys", GenerateKeys);
  Nan::SetPrototypeMethod(tpl, "getKeys", GetKeys);
  Nan::SetPrototypeMethod(tpl, "encrypt", Encrypt);
  // Test code
  Nan::SetPrototypeMethod(tpl, "getGazePoint", GetGazePoint);
  Nan::SetPrototypeMethod(tpl, "plusOne", PlusOne);

  constructor.Reset(tpl->GetFunction());
  exports->Set(Nan::New("ECIESWrapper").ToLocalChecked(), tpl->GetFunction());
}

// Constructor
void ECIESWrapper::New(const Nan::FunctionCallbackInfo<v8::Value>& args) {
  if (args.IsConstructCall()) {
    // Invoked as constructor: `new ECIESWrapper(...)`
    double value = args[0]->IsUndefined() ? 0 : args[0]->NumberValue();
    ECIESWrapper* obj = new ECIESWrapper(value);
    obj->Wrap(args.This());
    args.GetReturnValue().Set(args.This());
  } else {
    // Invoked as plain function `ECIESWrapper(...)`, turn into construct call.
    const int argc = 1;
    v8::Local<v8::Value> argv[argc] = { args[0] };
    v8::Local<v8::Function> cons = Nan::New<v8::Function>(constructor);
    args.GetReturnValue().Set(cons->NewInstance(argc, argv));
  }
}

// Get random keys
void ECIESWrapper::GenerateKeys(const Nan::FunctionCallbackInfo<v8::Value>& args) {
  char pubX[2 * ECIES_KEY_SIZE + 1], pubY[2 * ECIES_KEY_SIZE + 1], privK[2 * ECIES_KEY_SIZE + 1];

  ECIES_generate_keys(&ECIESWrapper::privateKey, &ECIESWrapper::publicKey);
  
  hex_dump(pubX, ECIESWrapper::publicKey.x, ECIES_KEY_SIZE);
  hex_dump(pubY, ECIESWrapper::publicKey.y, ECIES_KEY_SIZE);
  hex_dump(privK, ECIESWrapper::privateKey.k, ECIES_KEY_SIZE);

  printf("pubX : %s, pubY : %s \n priv : %s\n", pubX, pubY, privK);

  v8::Local<v8::Object> result = Nan::New<v8::Object>();
  v8::Local<v8::Object> resultPub = Nan::New<v8::Object>();
  resultPub->Set(Nan::New("x").ToLocalChecked(), Nan::CopyBuffer((char*)ECIESWrapper::publicKey.x, 21).ToLocalChecked());
  resultPub->Set(Nan::New("y").ToLocalChecked(), Nan::CopyBuffer((char*)ECIESWrapper::publicKey.y, 21).ToLocalChecked());
  result->Set(Nan::New("pub").ToLocalChecked(), resultPub);
  result->Set(Nan::New("priv").ToLocalChecked(), Nan::CopyBuffer((char*)ECIESWrapper::privateKey.k, 21).ToLocalChecked());

  args.GetReturnValue().Set(result);
}

// Get random keys
void ECIESWrapper::GetKeys(const Nan::FunctionCallbackInfo<v8::Value>& args) {
  v8::Local<v8::Object> result = Nan::New<v8::Object>();
  v8::Local<v8::Object> resultPub = Nan::New<v8::Object>();
  resultPub->Set(Nan::New("x").ToLocalChecked(), Nan::CopyBuffer((char*)ECIESWrapper::publicKey.x, 21).ToLocalChecked());
  resultPub->Set(Nan::New("y").ToLocalChecked(), Nan::CopyBuffer((char*)ECIESWrapper::publicKey.y, 21).ToLocalChecked());
  result->Set(Nan::New("pub").ToLocalChecked(), resultPub);
  result->Set(Nan::New("priv").ToLocalChecked(), Nan::CopyBuffer((char*)ECIESWrapper::privateKey.k, 21).ToLocalChecked());

  args.GetReturnValue().Set(result);
}

// Encryption
void ECIESWrapper::Encrypt(const Nan::FunctionCallbackInfo<v8::Value>& args) {
  v8::Local<v8::Object> bufferObj = args[0]->ToObject();
  char* text = (char*)node::Buffer::Data(bufferObj);
  uint32_t bufferLength = (uint32_t)node::Buffer::Length(bufferObj);

  printf("bufferData: %s\n, bufferLength %d\n", text, bufferLength);
  
  // ECIES_pubkey_t public2 = {
  //   { 0x01, 0xc5, 0x6d, 0x30, 0x2c, 0xf6, 0x42, 0xa8, 0xe1, 0xba, 0x4b, 0x48, 0xcc, 0x4f, 0xbe, 0x28, 0x45, 0xee, 0x32, 0xdc, 0xe7 },
  //   { 0x04, 0x5f, 0x46, 0xeb, 0x30, 0x3e, 0xdf, 0x2e, 0x62, 0xf7, 0x4b, 0xd6, 0x83, 0x68, 0xd9, 0x79, 0xe2, 0x65, 0xee, 0x3c, 0x03 },
  // };
  
  // ECIES_privkey_t private2 = {
  //   { 0x00, 0xe1, 0x0e, 0x78, 0x70, 0x36, 0x94, 0x1e, 0x6c, 0x78, 0xda, 0xf8, 0xa0, 0xe8, 0xe1, 0xdb, 0xfa, 0xc6, 0x8e, 0x26, 0xd2 },
  // };

  // ECIES_size_t len = bufferLength;
  // ECIES_byte_t *encrypted = (ECIES_byte_t*)malloc(len + ECIES_OVERHEAD);
  // char *decrypted = (char*)malloc(len);

  // printf("plain text: %s\n", text);
  // ECIES_encrypt(encrypted, text, len, &public2);   /* encryption */

  // char *buf = (char*)malloc(2 * (len + ECIES_OVERHEAD) + 1);
  // hex_dump(buf, encrypted, len + ECIES_OVERHEAD);
  
  // printf("encrypted hex: %s\n", buf);
  
  // free(buf);

  // if (ECIES_decrypt(decrypted, len, encrypted, &private2) < 0) /* decryption */
  //   printf("decryption failed!\n");
  // else
  //   printf("after encryption/decryption: %s\n", decrypted);

  // args.GetReturnValue().Set(Nan::CopyBuffer(text, bufferLength).ToLocalChecked());

  // free(encrypted);
  // free(decrypted);
}

// Test code
void ECIESWrapper::GetGazePoint(const Nan::FunctionCallbackInfo<v8::Value>& args) {
	// Isolate* isolate = args.GetIsolate();

	// Local<Function> cb = Local<Function>::Cast(args[0]);
	// const unsigned argc = 1;

	// EyeTracker *tracker = new EyeTracker();
	// CvBox2D pupilCenterPoint;
	// tracker->setup();

	// while(1) {
	// 	tracker->update();
	// 	pupilCenterPoint = tracker->getPupilCenterPoint();

	// 	// pack to json object
	// 	Local<Object> result = Object::New(isolate);
	// 	result->Set(String::NewFromUtf8(isolate, "x"), Number::New(isolate, pupilCenterPoint.center.x));
  //       result->Set(String::NewFromUtf8(isolate, "y"), Number::New(isolate, pupilCenterPoint.center.y));
	// 	Local<Value> argv[argc] = result;

	// 	cb->Call(Null(isolate), argc, argv);

	// }

}

void ECIESWrapper::PlusOne(const Nan::FunctionCallbackInfo<v8::Value>& args) {
  ECIESWrapper* obj = ObjectWrap::Unwrap<ECIESWrapper>(args.Holder());
  obj->value_ += 1;

  args.GetReturnValue().Set(Nan::New(obj->value_));
}

}  // namespace node_ecies
