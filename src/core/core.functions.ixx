module;

#include <core/core.h>

export module pkcs11:core.functions;

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
