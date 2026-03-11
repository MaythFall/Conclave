#pragma once
#include <cstdint>
#include <vector>
#include <string>
#include <stdexcept>
#include <set>
#if defined(__linux__) || defined(__unix__)
    #include <string.h>
#endif

namespace conclave {

     inline static void secureWipe(void *data, size_t size) noexcept {
        #if defined(_WIN32) || defined(_WIN64)
            SecureZeroMemory(data, size);
        #elif defined(__linux__) || defined(__FreeBSD__) || defined(__OpenBSD__)
            explicit_bzero(data, size);
        #elif defined(__STDC_LIB_EXT1__) || (__cplusplus >= 202302L)
            memset_explicit(data, 0, size);
        #else
            volatile unsigned char* p = static_cast<volatile unsigned char*>(data);
            while (size--) *p++ = 0;
        #endif
    }

    //Re-using from Divalia(Personal Project)
    template <typename T = uint8_t, size_t Align = 32>
    class SecureBuffer {
        private:
        template <typename U>
        struct AlignedAllocator {
            using value_type = U;

            U* allocate(size_t n) {
                if (n==0) return nullptr;

                size_t size = (n * sizeof(U) + Align - 1) & ~(Align - 1);
                void* ptr = std::aligned_alloc(Align, size);
                if (!ptr) throw std::bad_alloc();
                return static_cast<U*>(ptr);
            }

            void deallocate(U* p, size_t) noexcept {
                std::free(p);
            }
            template <typename V> struct rebind { using other = AlignedAllocator<V>; };

            bool operator==(const AlignedAllocator&) const noexcept { return true; }
            bool operator!=(const AlignedAllocator&) const noexcept { return false; }
        };

        std::vector<T, AlignedAllocator<T>> data_;
        
        public:
        explicit SecureBuffer(size_t size) : data_(size) {}
        SecureBuffer() = default;

        ~SecureBuffer() {
            if (!data_.empty()) {
                secureWipe(data_.data(), data_.size());
            }
        }

        SecureBuffer(const SecureBuffer&) = delete;
        SecureBuffer& operator=(const SecureBuffer&) = delete;

        SecureBuffer(SecureBuffer&&) noexcept = default;
        SecureBuffer& operator=(SecureBuffer&&) noexcept = default;

        T* data() { return data_.data(); }
        const T* data() const { return data_.data(); }
        size_t size() const { return data_.size(); }
        void resize(size_t count) { data_.resize(count); }
        void resize(size_t count, const T& value) { data_.resize(count, value); }
        T& operator[] (size_t pos) {return data_[pos];}
        T& operator[] (size_t pos) const {return data_[pos];}
        void emplace_back(T&& args) {data_.emplace_back(args);}
        bool empty() const { return data_.empty(); }
        auto begin() { return data_.begin(); }
        auto end() { return data_.end(); }
        void reserve(size_t size) const { data_.reserve(size); }
        T back() const { return data_.back(); }
        T front() const { return data_.front(); }

        template <typename InputIt>
        void insert(auto pos, InputIt first, InputIt last) {
            data_.insert(pos, first, last);
        }

    };
    using ID = int;
    using FDESC = int;

    enum class MessageType : uint8_t {
        MSG,
        CMD,
        ROOM_LIST
    };

    enum class Commands : uint8_t {
        JOIN,
        LEAVE,
        CREATE,
        DESTROY,
        DISCONNECT
    };

    struct Room {
        std::string name;
        std::string password;
        std::set<ID> users = {};
        Room(std::string n, std::string pw) : name(n), password(pw) {}
        Room() = default;
        ~Room() {
            secureWipe(password.data(), password.length());
            users.clear();
        }
    };

}