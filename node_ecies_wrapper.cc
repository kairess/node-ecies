// node_ecies_wrapper.cc
#include "node_ecies_wrapper.h"

namespace node_ecies {

Nan::Persistent<v8::Function> ECIESWrapper::constructor;

ECIES_privkey_t ECIESWrapper::privateKey = {};
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
  Nan::SetPrototypeMethod(tpl, "setClientPublicKey", SetClientPublicKey);
  Nan::SetPrototypeMethod(tpl, "setPrivateKey", SetPrivateKey);
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

// Get keys
void ECIESWrapper::GetKeys(const Nan::FunctionCallbackInfo<v8::Value>& args) {
  v8::Local<v8::Object> result = Nan::New<v8::Object>();
  v8::Local<v8::Object> resultPub = Nan::New<v8::Object>();
  resultPub->Set(Nan::New("x").ToLocalChecked(), Nan::CopyBuffer((char*)ECIESWrapper::publicKey.x, 21).ToLocalChecked());
  resultPub->Set(Nan::New("y").ToLocalChecked(), Nan::CopyBuffer((char*)ECIESWrapper::publicKey.y, 21).ToLocalChecked());
  result->Set(Nan::New("pub").ToLocalChecked(), resultPub);
  result->Set(Nan::New("priv").ToLocalChecked(), Nan::CopyBuffer((char*)ECIESWrapper::privateKey.k, 21).ToLocalChecked());

  args.GetReturnValue().Set(result);
}

// Set public key
void ECIESWrapper::SetClientPublicKey(const Nan::FunctionCallbackInfo<v8::Value>& args) {
  v8::Local<v8::Object> x_object = args[0]->ToObject();
  char* x = (char*)node::Buffer::Data(x_object);
  uint32_t x_length = (uint32_t)node::Buffer::Length(x_object);

  v8::Local<v8::Object> y_object = args[1]->ToObject();
  char* y = (char*)node::Buffer::Data(y_object);
  uint32_t y_length = (uint32_t)node::Buffer::Length(y_object);

  memcpy(ECIESWrapper::publicKey.x, x, x_length);
  memcpy(ECIESWrapper::publicKey.y, y, y_length);

  v8::Local<v8::Object> resultPub = Nan::New<v8::Object>();
  resultPub->Set(Nan::New("x").ToLocalChecked(), Nan::CopyBuffer((char*)ECIESWrapper::publicKey.x, 21).ToLocalChecked());
  resultPub->Set(Nan::New("y").ToLocalChecked(), Nan::CopyBuffer((char*)ECIESWrapper::publicKey.y, 21).ToLocalChecked());

  args.GetReturnValue().Set(resultPub);
}

// Set private key
void ECIESWrapper::SetPrivateKey(const Nan::FunctionCallbackInfo<v8::Value>& args) {
  v8::Local<v8::Object> priv_object = args[0]->ToObject();
  char* priv = (char*)node::Buffer::Data(priv_object);
  uint32_t priv_length = (uint32_t)node::Buffer::Length(priv_object);

  memcpy(ECIESWrapper::privateKey.k, priv, priv_length);

  args.GetReturnValue().Set(Nan::CopyBuffer((char*)ECIESWrapper::privateKey.k, 21).ToLocalChecked());
}

// Encryption
void ECIESWrapper::Encrypt(const Nan::FunctionCallbackInfo<v8::Value>& args) {
  v8::Local<v8::Object> text_object = args[0]->ToObject();
  char* text = (char*)node::Buffer::Data(text_object);
  uint32_t text_length = (uint32_t)node::Buffer::Length(text_object);

  // printf("plain text: %s, length: %d ", text, text_length);

  // v8::Local<v8::Object> pub_object = args[1]->ToObject();
  // char* pub = (char*)node::Buffer::Data(pub_object);
  // uint32_t pub_object_length = (uint32_t)node::Buffer::Length(pub_object);

  ECIES_size_t len = text_length;
  ECIES_byte_t *encrypted = (ECIES_byte_t*)malloc(len + ECIES_OVERHEAD);
  char *decrypted = (char*)malloc(len);
  
  ECIES_encrypt(encrypted, text, len, &ECIESWrapper::publicKey);

  args.GetReturnValue().Set(Nan::CopyBuffer(reinterpret_cast<char*>(encrypted), len + ECIES_OVERHEAD).ToLocalChecked());

  char *buf = (char*)malloc(2 * (len + ECIES_OVERHEAD) + 1);
  hex_dump(buf, encrypted, len + ECIES_OVERHEAD);
  printf("encrypted hex: %s\n", buf);
  free(buf);

  if (ECIES_decrypt(decrypted, len, encrypted, &ECIESWrapper::privateKey) < 0) /* decryption */
    printf("decryption failed!\n");
  else
    printf("after encryption/decryption: %s\n", decrypted);

  // args.GetReturnValue().Set(Nan::CopyBuffer(reinterpret_cast<char*>(text), len).ToLocalChecked());

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
