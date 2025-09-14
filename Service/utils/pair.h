#pragma once
namespace UTIL {
    template <typename A, typename B> class Pair {
        A varA;
        B varB;
    public:
        Pair(A a, B b) : varA(a), varB(b) {}
        A getA() const { return varA; }
        const B& getB() const { return varB; }
        void setA(const A& val) { varA = val; }
        void setB(const B& val) { varB = val; }
    };
}