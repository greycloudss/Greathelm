#pragma once
namespace UTIL {
    template <typename A, typename B> class Pair {
        private:
            A varA;
            B varB;
        public:
            Pair(A varA, B varB) : varA(varA), varB(varB) { }
            
            Pair<A, B> getPair() {
                return this;
            }

            A getA() {
                return A;
            }

            B getB() {
                return B;
            }

            void setA(A valA) {
                this.valA = valA;
            }

            void setB(B valB) {
                this.valB = valB;
            }
    };
};