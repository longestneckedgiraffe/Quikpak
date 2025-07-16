#include <iostream>
#include <string>
#include <vector>
#include <chrono>

const char* app_data = ";WSqiW.p,*qSRU/(wG/-_J$U+.{@K:AV{D}(}[vkxg3&CkKq#Szbnmzcz;$XWUyfcGe&=n:0%k-Jq%}Q.yrB.@Paq@LE:C6E6m!MGi{=-Nu9}=cJ@{8PW5mW.0N5M0Qj";
int global_value = 42;
std::vector<int> numbers = { 1, 2, 3, 4, 5 };
volatile uint64_t fibonacci_result = 0;
volatile double computation_time_ms = 0.0;

int calculate_sum();
void process_data();
std::string get_result();
uint64_t calculate_fibonacci(int n);
void perform_heavy_computation();

int main() {
    calculate_sum();
    process_data();
    perform_heavy_computation();
    get_result();
    return 0;
}

int calculate_sum() {
    int sum = 0;
    for (const auto& num : numbers) {
        sum += num;
    }
    global_value += sum;
    return sum;
}

void process_data() {
    std::string temp = app_data;
    temp += "_processed";

    char buffer[128];
    sprintf_s(buffer, sizeof(buffer), "Value: %d", global_value);

    auto* dynamic_data = new int[10];
    for (int i = 0; i < 10; ++i) {
        dynamic_data[i] = i * global_value;
    }
    delete[] dynamic_data;
}

std::string get_result() {
    return std::string(app_data) + std::to_string(global_value);
}

uint64_t calculate_fibonacci(int n) {
    if (n <= 1) return n;

    uint64_t a = 0, b = 1;
    for (int i = 2; i <= n; ++i) {
        uint64_t temp = a + b;
        a = b;
        b = temp;
    }
    return b;
}

void perform_heavy_computation() {
    auto start = std::chrono::high_resolution_clock::now();

    fibonacci_result = calculate_fibonacci(50);

    volatile uint64_t prime_sum = 0;
    for (int i = 2; i < 10000; ++i) {
        bool is_prime = true;
        for (int j = 2; j * j <= i; ++j) {
            if (i % j == 0) {
                is_prime = false;
                break;
            }
        }
        if (is_prime) {
            prime_sum += i;
        }
    }

    const int matrix_size = 100;
    volatile int matrix_result = 0;
    for (int i = 0; i < matrix_size; ++i) {
        for (int j = 0; j < matrix_size; ++j) {
            for (int k = 0; k < matrix_size; ++k) {
                matrix_result += (i * j * k) % 1000;
            }
        }
    }

    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
    computation_time_ms = duration.count() / 1000.0;

    std::cout << "Fibonacci(50): " << fibonacci_result << std::endl;
    std::cout << "Prime sum: " << prime_sum << std::endl;
    std::cout << "Computation time: " << computation_time_ms << " ms" << std::endl;

    global_value += static_cast<int>(fibonacci_result % 1000);
    global_value += static_cast<int>(prime_sum % 1000);
    global_value += matrix_result % 1000;
}