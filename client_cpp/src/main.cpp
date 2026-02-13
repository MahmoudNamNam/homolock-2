/**
 * HomoLock-HR C++ Client
 * CLI for privacy-preserving HR/payroll computations using Microsoft SEAL (BFV).
 * Compile and run on Ubuntu 22.04.
 */

#include <seal/seal.h>
#include <curl/curl.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <algorithm>
#include <chrono>
#include <iomanip>

#ifdef _WIN32
#include <winsock2.h>
#pragma comment(lib, "ws2_32.lib")
#endif

using namespace seal;

// ---------------------------------------------------------------------------
// I/O and Base64 helpers
// ---------------------------------------------------------------------------

std::vector<uint8_t> read_file_bytes(const std::string& path) {
    std::ifstream f(path, std::ios::binary | std::ios::ate);
    if (!f) throw std::runtime_error("Cannot open file: " + path);
    auto size = f.tellg();
    f.seekg(0);
    std::vector<uint8_t> buf(size);
    if (!f.read(reinterpret_cast<char*>(buf.data()), size))
        throw std::runtime_error("Read failed: " + path);
    return buf;
}

void write_file_bytes(const std::string& path, const void* data, size_t size) {
    std::ofstream f(path, std::ios::binary);
    if (!f) throw std::runtime_error("Cannot write file: " + path);
    f.write(reinterpret_cast<const char*>(data), size);
}

static const char b64_table[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

std::string b64_encode(const uint8_t* data, size_t len) {
    std::string out;
    out.reserve(((len + 2) / 3) * 4);
    for (size_t i = 0; i < len; i += 3) {
        uint32_t n = (uint32_t)data[i] << 16;
        if (i + 1 < len) n |= (uint32_t)data[i + 1] << 8;
        if (i + 2 < len) n |= (uint32_t)data[i + 2];
        out += b64_table[(n >> 18) & 63];
        out += b64_table[(n >> 12) & 63];
        out += (i + 1 < len) ? b64_table[(n >> 6) & 63] : '=';
        out += (i + 2 < len) ? b64_table[n & 63] : '=';
    }
    return out;
}

std::string b64_encode(const std::vector<uint8_t>& data) {
    return b64_encode(data.data(), data.size());
}

static inline int b64_char_value(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

std::vector<uint8_t> b64_decode(const std::string& str) {
    std::vector<uint8_t> out;
    size_t n = str.size();
    out.reserve((n * 3) / 4);
    for (size_t i = 0; i + 4 <= n; i += 4) {
        int a = b64_char_value(str[i]);
        int b = b64_char_value(str[i + 1]);
        int c = b64_char_value(str[i + 2]);
        int d = b64_char_value(str[i + 3]);
        if (a < 0 || b < 0) break;
        out.push_back(static_cast<uint8_t>((a << 2) | (b >> 4)));
        if (c >= 0)
            out.push_back(static_cast<uint8_t>((b << 4) | (c >> 2)));
        if (d >= 0)
            out.push_back(static_cast<uint8_t>((c << 6) | d));
    }
    return out;
}

// ---------------------------------------------------------------------------
// HTTP with libcurl
// ---------------------------------------------------------------------------

struct CurlBuffer {
    std::string data;
};
static size_t curl_write_cb(void* ptr, size_t size, size_t nmemb, void* user) {
    size_t total = size * nmemb;
    auto* buf = static_cast<CurlBuffer*>(user);
    buf->data.append(static_cast<char*>(ptr), total);
    return total;
}

std::string http_post_json(const std::string& url, const std::string& json) {
    CURL* curl = curl_easy_init();
    if (!curl) throw std::runtime_error("curl_easy_init failed");
    CurlBuffer buf;
    struct curl_slist* headers = nullptr;
    headers = curl_slist_append(headers, "Content-Type: application/json");
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json.c_str());
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &buf);
    CURLcode res = curl_easy_perform(curl);
    curl_slist_free_all(headers);
    if (res != CURLE_OK) {
        curl_easy_cleanup(curl);
        throw std::runtime_error(std::string("curl failed: ") + curl_easy_strerror(res));
    }
    long code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &code);
    curl_easy_cleanup(curl);
    if (code < 200 || code >= 300)
        throw std::runtime_error("HTTP " + std::to_string(code) + ": " + buf.data);
    return buf.data;
}

std::string http_get(const std::string& url) {
    CURL* curl = curl_easy_init();
    if (!curl) throw std::runtime_error("curl_easy_init failed");
    CurlBuffer buf;
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &buf);
    CURLcode res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        curl_easy_cleanup(curl);
        throw std::runtime_error(std::string("curl failed: ") + curl_easy_strerror(res));
    }
    long code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &code);
    curl_easy_cleanup(curl);
    if (code < 200 || code >= 300)
        throw std::runtime_error("HTTP " + std::to_string(code) + ": " + buf.data);
    return buf.data;
}

// Simple JSON escape and field helpers (minimal for MVP)
std::string json_escape(const std::string& s) {
    std::string out;
    out.reserve(s.size() + 8);
    for (char c : s) {
        if (c == '"') out += "\\\"";
        else if (c == '\\') out += "\\\\";
        else if (c == '\n') out += "\\n";
        else out += c;
    }
    return out;
}

// ---------------------------------------------------------------------------
// UUID (simple random hex id if no libuuid)
// ---------------------------------------------------------------------------
std::string generate_session_id() {
    static const char hex[] = "0123456789abcdef";
    std::string id = "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx";
    std::srand(static_cast<unsigned>(std::time(nullptr)));
    for (char& c : id) {
        if (c == 'x') c = hex[std::rand() % 16];
        else if (c == 'y') c = hex[(std::rand() % 4) + 8];
    }
    return id;
}

// ---------------------------------------------------------------------------
// Subcommand: init-context
// ---------------------------------------------------------------------------
void cmd_init_context(int poly_degree) {
    std::string out_dir = "out";
    std::string params_path = out_dir + "/params.seal";
    std::cout << "Creating BFV parameters (poly_modulus_degree=" << poly_degree << ") ...\n";

    EncryptionParameters parms(scheme_type::bfv);
    parms.set_poly_modulus_degree(static_cast<size_t>(poly_degree));
    parms.set_coeff_modulus(CoeffModulus::BFVDefault(static_cast<size_t>(poly_degree)));
    parms.set_plain_modulus(PlainModulus::Batching(static_cast<size_t>(poly_degree), 20));

    SEALContext context(parms);
    {
        std::string err = context.parameter_error_message();
        if (!err.empty() && err != "valid") {
            std::cerr << "Parameter error: " << err << "\n";
            throw std::runtime_error("Invalid SEAL parameters");
        }
    }

    std::ofstream of(params_path, std::ios::binary);
    if (!of) throw std::runtime_error("Cannot write " + params_path);
    parms.save(of);
    of.close();

    std::cout << "Parameters written to " << params_path << "\n";
    std::cout << "  poly_modulus_degree: " << poly_degree << " (slot count for batching)\n";
    std::cout << "  coeff_modulus: BFVDefault (security + noise budget)\n";
    std::cout << "  plain_modulus: Batching prime (~20 bits, enables SIMD slots)\n";
}

// ---------------------------------------------------------------------------
// Subcommand: keygen
// ---------------------------------------------------------------------------
void cmd_keygen() {
    std::string out_dir = "out";
    std::string params_path = out_dir + "/params.seal";
    std::string sk_path = out_dir + "/secret_key.seal";
    std::string pk_path = out_dir + "/public_key.seal";
    std::string relin_path = out_dir + "/relin_keys.seal";
    std::string galois_path = out_dir + "/galois_keys.seal";

    auto buf = read_file_bytes(params_path);
    EncryptionParameters parms;
    parms.load(reinterpret_cast<const std::byte*>(buf.data()), buf.size());
    SEALContext context(parms);

    KeyGenerator keygen(context);
    SecretKey secret_key = keygen.secret_key();
    PublicKey public_key;
    keygen.create_public_key(public_key);
    RelinKeys relin_keys;
    keygen.create_relin_keys(relin_keys);
    GaloisKeys galois_keys;
    keygen.create_galois_keys(galois_keys);

    {
        std::ofstream of(sk_path, std::ios::binary);
        secret_key.save(of);
    }
    {
        std::ofstream of(pk_path, std::ios::binary);
        public_key.save(of);
    }
    {
        std::ofstream of(relin_path, std::ios::binary);
        relin_keys.save(of);
    }
    {
        std::ofstream of(galois_path, std::ios::binary);
        galois_keys.save(of);
    }

    std::cout << "Keys written:\n";
    std::cout << "  " << sk_path << "\n";
    std::cout << "  " << pk_path << "\n";
    std::cout << "  " << relin_path << "\n";
    std::cout << "  " << galois_path << "\n";
    std::cerr << "\n*** NEVER upload secret_key.seal to the server ***\n\n";
}

// ---------------------------------------------------------------------------
// Subcommand: encrypt-hr (CSV -> ciphertexts)
// ---------------------------------------------------------------------------
struct EmployeeRow {
    int64_t employee_id;
    int64_t salary_cents;
    int64_t hours;
    int64_t bonus_points;
};

std::vector<EmployeeRow> parse_employees_csv(const std::string& path) {
    std::ifstream f(path);
    if (!f) throw std::runtime_error("Cannot open " + path);
    std::string line;
    std::vector<EmployeeRow> rows;
    if (!std::getline(f, line)) throw std::runtime_error("Empty CSV");
    // header: employee_id,salary_cents,hours,bonus_points
    while (std::getline(f, line)) {
        if (line.empty()) continue;
        EmployeeRow r{};
        size_t pos = 0;
        auto next = [&]() {
            size_t end = line.find(',', pos);
            std::string s = (end == std::string::npos) ? line.substr(pos) : line.substr(pos, end - pos);
            pos = (end == std::string::npos) ? line.size() : end + 1;
            return s;
        };
        r.employee_id = std::stoll(next());
        r.salary_cents = std::stoll(next());
        r.hours = std::stoll(next());
        r.bonus_points = std::stoll(next());
        rows.push_back(r);
    }
    return rows;
}

void cmd_encrypt_hr() {
    std::string out_dir = "out";
    std::string data_dir = "data";
    std::string csv_path = data_dir + "/employees.csv";
    std::string params_path = out_dir + "/params.seal";
    std::string pk_path = out_dir + "/public_key.seal";

    auto rows = parse_employees_csv(csv_path);
    size_t n = rows.size();
    std::cout << "Loaded " << n << " employees from " << csv_path << "\n";

    auto parms_buf = read_file_bytes(params_path);
    EncryptionParameters parms;
    parms.load(reinterpret_cast<const std::byte*>(parms_buf.data()), parms_buf.size());
    SEALContext context(parms);
    PublicKey public_key;
    {
        auto pk_buf = read_file_bytes(pk_path);
        public_key.load(context, reinterpret_cast<const std::byte*>(pk_buf.data()), pk_buf.size());
    }
    Encryptor encryptor(context, public_key);
    BatchEncoder batch_encoder(context);
    size_t slot_count = batch_encoder.slot_count();

    auto encrypt_vector = [&](const std::vector<uint64_t>& values) {
        std::vector<Ciphertext> cts;
        for (uint64_t v : values) {
            std::vector<uint64_t> slot(slot_count, 0);
            slot[0] = v;
            Plaintext pt;
            batch_encoder.encode(slot, pt);
            Ciphertext ct;
            encryptor.encrypt(pt, ct);
            cts.push_back(std::move(ct));
        }
        return cts;
    };

    std::vector<uint64_t> salaries(n), hours(n), bonus_pts(n);
    for (size_t i = 0; i < n; i++) {
        salaries[i] = static_cast<uint64_t>(rows[i].salary_cents);
        hours[i] = static_cast<uint64_t>(rows[i].hours);
        bonus_pts[i] = static_cast<uint64_t>(rows[i].bonus_points);
    }

    auto salary_cts = encrypt_vector(salaries);
    auto hours_cts = encrypt_vector(hours);
    auto bonus_cts = encrypt_vector(bonus_pts);

    auto save_ct_vec = [](const std::string& path, const std::vector<Ciphertext>& cts, SEALContext& ctx) {
        std::ofstream of(path, std::ios::binary);
        if (!of) throw std::runtime_error("Cannot write " + path);
        uint32_t count = static_cast<uint32_t>(cts.size());
        of.write(reinterpret_cast<const char*>(&count), 4);
        for (const auto& ct : cts) {
            std::ostringstream oss;
            ct.save(oss);
            std::string s = oss.str();
            uint32_t len = static_cast<uint32_t>(s.size());
            of.write(reinterpret_cast<const char*>(&len), 4);
            of.write(s.data(), len);
        }
    };
    save_ct_vec(out_dir + "/salary.ct", salary_cts, context);
    save_ct_vec(out_dir + "/hours.ct", hours_cts, context);
    save_ct_vec(out_dir + "/bonus_points.ct", bonus_cts, context);

    // meta.json
    auto now = std::chrono::system_clock::now();
    auto t = std::chrono::system_clock::to_time_t(now);
    std::ostringstream meta;
    meta << "{\"count\":" << n << ",\"version\":1,\"created_at\":\"" << std::put_time(std::gmtime(&t), "%Y-%m-%dT%H:%M:%SZ") << "\"}";
    write_file_bytes(out_dir + "/meta.json", meta.str().data(), meta.str().size());

    std::cout << "Written out/salary.ct, out/hours.ct, out/bonus_points.ct, out/meta.json\n";
}

// ---------------------------------------------------------------------------
// Subcommand: upload-session
// ---------------------------------------------------------------------------
void cmd_upload_session(const std::string& base_url, std::string session_id) {
    if (session_id.empty()) session_id = generate_session_id();
    std::string out_dir = "out";

    std::string params_b64 = b64_encode(read_file_bytes(out_dir + "/params.seal"));
    std::string pk_b64 = b64_encode(read_file_bytes(out_dir + "/public_key.seal"));
    std::string relin_b64 = b64_encode(read_file_bytes(out_dir + "/relin_keys.seal"));
    std::string galois_b64 = b64_encode(read_file_bytes(out_dir + "/galois_keys.seal"));

    std::ostringstream json;
    json << "{\"session_id\":\"" << json_escape(session_id) << "\","
         << "\"params_b64\":\"" << json_escape(params_b64) << "\","
         << "\"public_key_b64\":\"" << json_escape(pk_b64) << "\","
         << "\"relin_keys_b64\":\"" << json_escape(relin_b64) << "\","
         << "\"galois_keys_b64\":\"" << json_escape(galois_b64) << "\"}";

    std::string url = base_url + "/v1/session/keys";
    std::string resp = http_post_json(url, json.str());
    std::cout << "Session keys uploaded. session_id=" << session_id << "\n";
}

// ---------------------------------------------------------------------------
// Subcommand: upload-data
// ---------------------------------------------------------------------------
void cmd_upload_data(const std::string& base_url, const std::string& session_id) {
    if (session_id.empty()) throw std::runtime_error("--session <id> required");
    std::string out_dir = "out";

    std::string salary_b64 = b64_encode(read_file_bytes(out_dir + "/salary.ct"));
    std::string hours_b64 = b64_encode(read_file_bytes(out_dir + "/hours.ct"));
    std::string bonus_b64 = b64_encode(read_file_bytes(out_dir + "/bonus_points.ct"));

    size_t count = 0;
    {
        std::ifstream m(out_dir + "/meta.json");
        std::string line;
        while (std::getline(m, line)) {
            auto p = line.find("\"count\":");
            if (p != std::string::npos) {
                count = static_cast<size_t>(std::stoll(line.substr(p + 8)));
                break;
            }
        }
    }
    if (count == 0) throw std::runtime_error("Could not read count from meta.json");

    std::ostringstream json;
    json << "{\"session_id\":\"" << json_escape(session_id) << "\","
         << "\"salary_ct_b64\":\"" << json_escape(salary_b64) << "\","
         << "\"hours_ct_b64\":\"" << json_escape(hours_b64) << "\","
         << "\"bonus_points_ct_b64\":\"" << json_escape(bonus_b64) << "\","
         << "\"count\":" << count << "}";

    std::string url = base_url + "/v1/session/data";
    http_post_json(url, json.str());
    std::cout << "Data uploaded for session " << session_id << "\n";
}

// ---------------------------------------------------------------------------
// Subcommand: compute (trigger jobs, print job_ids)
// ---------------------------------------------------------------------------
std::string extract_job_id(const std::string& json) {
    auto p = json.find("\"job_id\":\"");
    if (p == std::string::npos) return "";
    p += 10;
    auto q = json.find('"', p);
    if (q == std::string::npos) return "";
    return json.substr(p, q - p);
}

void cmd_compute(const std::string& base_url, const std::string& session_id,
                 int bonus_rate_bps) {
    if (session_id.empty()) throw std::runtime_error("--session <id> required");
    std::string body = "{\"session_id\":\"" + json_escape(session_id) + "\"}";

    auto post = [&](const std::string& path) -> std::string {
        return http_post_json(base_url + path, body);
    };

    std::string r1 = post("/v1/compute/total_payroll");
    std::cout << "total_payroll job_id=" << extract_job_id(r1) << "\n";

    std::string r2 = post("/v1/compute/avg_salary");
    std::cout << "avg_salary job_id=" << extract_job_id(r2) << "\n";

    std::string r3 = post("/v1/compute/total_hours");
    std::cout << "total_hours job_id=" << extract_job_id(r3) << "\n";

    std::string body_bonus = "{\"session_id\":\"" + json_escape(session_id) + "\",\"bonus_rate_bps\":" + std::to_string(bonus_rate_bps) + "}";
    std::string r4 = http_post_json(base_url + "/v1/compute/bonus_pool", body_bonus);
    std::cout << "bonus_pool job_id=" << extract_job_id(r4) << "\n";
}

// ---------------------------------------------------------------------------
// Subcommand: fetch-and-decrypt
// ---------------------------------------------------------------------------
void cmd_fetch_decrypt(const std::string& base_url, const std::string& job_id) {
    if (job_id.empty()) throw std::runtime_error("--job-id <id> required");
    std::string out_dir = "out";
    std::string url = base_url + "/v1/result/" + job_id;
    std::string resp = http_get(url);
    // Parse minimal: "result_ciphertext_b64":"...", "result_type":"...", "count":N
    std::string result_b64;
    std::string result_type;
    size_t count = 0;
    auto extract = [&](const std::string& key, std::string& out_s) {
        std::string q = "\"" + key + "\":\"";
        auto p = resp.find(q);
        if (p != std::string::npos) {
            p += q.size();
            auto end = resp.find('"', p);
            while (end != std::string::npos && resp[end - 1] == '\\') end = resp.find('"', end + 1);
            if (end != std::string::npos) out_s = resp.substr(p, end - p);
        }
    };
    auto extract_num = [&](const std::string& key) -> size_t {
        std::string q = "\"" + key + "\":";
        auto p = resp.find(q);
        if (p == std::string::npos) return 0;
        p += q.size();
        size_t v = 0;
        while (p < resp.size() && std::isdigit(resp[p])) { v = v * 10 + (resp[p++] - '0'); }
        return v;
    };
    extract("result_ciphertext_b64", result_b64);
    extract("result_type", result_type);
    count = extract_num("count");

    if (result_b64.empty()) {
        std::cerr << "No result_ciphertext_b64 in response. Response: " << resp << "\n";
        throw std::runtime_error("Invalid result response");
    }

    auto ct_bin = b64_decode(result_b64);
    auto parms_buf = read_file_bytes(out_dir + "/params.seal");
    EncryptionParameters parms;
    parms.load(reinterpret_cast<const std::byte*>(parms_buf.data()), parms_buf.size());
    SEALContext context(parms);
    SecretKey secret_key;
    {
        auto sk_buf = read_file_bytes(out_dir + "/secret_key.seal");
        secret_key.load(context, reinterpret_cast<const std::byte*>(sk_buf.data()), sk_buf.size());
    }
    Decryptor decryptor(context, secret_key);
    BatchEncoder batch_encoder(context);

    Ciphertext ct;
    ct.load(context, reinterpret_cast<const std::byte*>(ct_bin.data()), ct_bin.size());
    Plaintext pt;
    decryptor.decrypt(ct, pt);
    std::vector<uint64_t> slots(batch_encoder.slot_count());
    batch_encoder.decode(pt, slots);
    uint64_t value = slots[0];

    if (result_type == "total_payroll") {
        std::cout << "Total payroll (cents): " << value << "\n";
        std::cout << "Formatted: " << (value / 100) << "." << std::setfill('0') << std::setw(2) << (value % 100) << " (units)\n";
    } else if (result_type == "avg_salary") {
        if (count == 0) count = 1;
        double avg = static_cast<double>(value) / count;
        std::cout << "Sum (cents): " << value << ", count: " << count << "\n";
        std::cout << "Average salary (cents): " << std::fixed << std::setprecision(2) << avg << "\n";
    } else if (result_type == "total_hours") {
        std::cout << "Total hours: " << value << "\n";
    } else if (result_type == "bonus_pool") {
        std::cout << "Encrypted sum(salary) decrypted (cents): " << value << "\n";
        std::cout << "(Compute bonus_pool = sum * bonus_rate_bps / 10000 on client if needed.)\n";
    } else {
        std::cout << "Result (" << result_type << "): " << value << "\n";
    }
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------
void print_usage(const char* prog) {
    std::cerr << "Usage: " << prog << " <command> [options]\n"
              << "  init-context [--poly 4096|8192]   Create params.seal (default poly=8192)\n"
              << "  keygen                              Generate secret/public/relin/galois keys\n"
              << "  encrypt-hr                         Encrypt data/employees.csv -> out/*.ct\n"
              << "  upload-session [--server URL] [--session ID]  Upload keys (default http://127.0.0.1:8000)\n"
              << "  upload-data --session ID [--server URL]\n"
              << "  compute --session ID [--server URL] [--bonus-bps 1000]\n"
              << "  fetch-and-decrypt --job-id ID [--server URL]\n";
}

int main(int argc, char* argv[]) {
    curl_global_init(CURL_GLOBAL_DEFAULT);
    int poly = 8192;
    std::string server = "http://127.0.0.1:8000";
    std::string session_id;
    std::string job_id;
    int bonus_bps = 1000;

    auto get_opt = [&](int i, const std::string& key) -> std::string {
        if (i + 1 >= argc) throw std::runtime_error("Missing value for " + key);
        return argv[i + 1];
    };

    if (argc < 2) { print_usage(argv[0]); return 1; }
    std::string cmd = argv[1];
    for (int i = 2; i < argc; i++) {
        if (std::string(argv[i]) == "--poly") { poly = std::stoi(get_opt(i, "--poly")); i++; }
        else if (std::string(argv[i]) == "--server") { server = get_opt(i, "--server"); i++; }
        else if (std::string(argv[i]) == "--session") { session_id = get_opt(i, "--session"); i++; }
        else if (std::string(argv[i]) == "--job-id") { job_id = get_opt(i, "--job-id"); i++; }
        else if (std::string(argv[i]) == "--bonus-bps") { bonus_bps = std::stoi(get_opt(i, "--bonus-bps")); i++; }
    }

    try {
        if (cmd == "init-context") cmd_init_context(poly);
        else if (cmd == "keygen") cmd_keygen();
        else if (cmd == "encrypt-hr") cmd_encrypt_hr();
        else if (cmd == "upload-session") cmd_upload_session(server, session_id);
        else if (cmd == "upload-data") cmd_upload_data(server, session_id);
        else if (cmd == "compute") cmd_compute(server, session_id, bonus_bps);
        else if (cmd == "fetch-and-decrypt") cmd_fetch_decrypt(server, job_id);
        else { print_usage(argv[0]); return 1; }
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        curl_global_cleanup();
        return 1;
    }
    curl_global_cleanup();
    return 0;
}
