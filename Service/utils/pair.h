namespace UTIL {
    template <typename A, typename B> class Pair {
        private:
            A varA;
            B varB;
        public:
            Pair(A a, B b) : varA(a), varB(b) {}
        
            A getA() { return varA; }
            B getB() { return varB; }
        
            void setA(A val) { varA = val; }
            void setB(B val) { varB = val; }
    };
}