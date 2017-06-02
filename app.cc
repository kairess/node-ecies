// app.cc
#include <nan.h>
#include "node_ecies_wrapper.h"

namespace node_ecies {

void InitAll(v8::Local<v8::Object> exports) {
	ECIESWrapper::Init(exports);
}

NODE_MODULE(addon, InitAll)

}  // namespace node_ecies
