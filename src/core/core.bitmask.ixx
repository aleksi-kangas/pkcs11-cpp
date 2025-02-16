module;

#include <type_traits>
#include <utility>

export module pkcs11:core.bitmask;

namespace pkcs11 {
    /**
     * Enables to opt in an enum for bitwise OR <code>|</code> -operator, allowing the enum to be used as a bitmask.
     */
    export template<typename T>
        requires(std::is_enum_v<T> and requires(T e)
        {
            enable_bitmask_operator_or(e);
        })
    constexpr auto
    operator|(const T lhs, const T rhs) {
        return static_cast<T>(std::to_underlying(lhs) |
                              std::to_underlying(rhs));
    }
} // namespace pkcs11
