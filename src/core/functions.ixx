module;

#pragma pack(push, cryptoki, 1)
#define CK_PTR *
#define CK_DECLARE_FUNCTION(returnType, name) returnType __declspec(dllimport) name
#define CK_DECLARE_FUNCTION_POINTER(returnType, name) returnType __declspec(dllimport) (* name)
#define CK_CALLBACK_FUNCTION(returnType, name) returnType (* name)
#include <pkcs11/pkcs11.h>
#pragma pack(pop, cryptoki)

export module pkcs11:functions;

namespace pkcs11 {
    export class FunctionListProvider {
    public:
        explicit FunctionListProvider(CK_FUNCTION_LIST_PTR f);

        [[nodiscard]] CK_FUNCTION_LIST_PTR F() const;

    private:
        CK_FUNCTION_LIST_PTR f_;
    };

    FunctionListProvider::FunctionListProvider(CK_FUNCTION_LIST_PTR f) : f_{f} {
    }

    CK_FUNCTION_LIST_PTR FunctionListProvider::F() const {
        return f_;
    }
} // namespace pkcs11
