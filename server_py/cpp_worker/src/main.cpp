/**
 * HomoLock-HR C++ Worker
 * Runs on the server; performs BFV homomorphic sum on ciphertexts.
 * Does NOT load or use the secret key — only params, relin keys, and input ciphertexts.
 */

#include <seal/seal.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <cstddef>
#include <cstdint>
#include <cstring>

using namespace seal;

static std::vector<uint8_t> read_file(const std::string& path) {
    std::ifstream f(path, std::ios::binary | std::ios::ate);
    if (!f) {
        std::cerr << "Cannot open: " << path << std::endl;
        throw std::runtime_error("Cannot open " + path);
    }
    auto size = f.tellg();
    f.seekg(0);
    std::vector<uint8_t> buf(static_cast<size_t>(size));
    if (!f.read(reinterpret_cast<char*>(buf.data()), size))
        throw std::runtime_error("Read failed: " + path);
    return buf;
}

static void write_file(const std::string& path, const std::string& data) {
    std::ofstream f(path, std::ios::binary);
    if (!f) throw std::runtime_error("Cannot write " + path);
    f.write(data.data(), data.size());
}

/** Load vector of ciphertexts from file: [uint32_t count][uint32_t len1][ct1...][len2][ct2...] */
static std::vector<Ciphertext> load_ct_vector(const std::string& path, const SEALContext& seal_ctx) {
    auto buf = read_file(path);
    if (buf.size() < 4) throw std::runtime_error("ct file too short");
    uint32_t count;
    std::memcpy(&count, buf.data(), 4);
    std::vector<Ciphertext> cts;
    size_t offset = 4;
    for (uint32_t i = 0; i < count && offset + 4 <= buf.size(); i++) {
        uint32_t len;
        std::memcpy(&len, buf.data() + offset, 4);
        offset += 4;
        if (offset + len > buf.size()) throw std::runtime_error("ct file truncated");
        Ciphertext ct;
        ct.load(seal_ctx, reinterpret_cast<const std::byte*>(buf.data() + offset), len);
        offset += len;
        cts.push_back(std::move(ct));
    }
    return cts;
}

static void save_ct(const std::string& path, const Ciphertext& ct) {
    std::ostringstream oss;
    ct.save(oss);
    write_file(path, oss.str());
}

static std::string get_opt(int argc, char** argv, const std::string& key) {
    for (int i = 1; i + 1 < argc; i++) {
        if (argv[i] == key) return argv[i + 1];
    }
    return "";
}

int main(int argc, char* argv[]) {
    std::string op = get_opt(argc, argv, "--op");
    std::string params_path = get_opt(argc, argv, "--params");
    std::string relin_path = get_opt(argc, argv, "--relin");
    std::string pk_path = get_opt(argc, argv, "--pk");
    std::string in_path = get_opt(argc, argv, "--in");
    std::string out_path = get_opt(argc, argv, "--out");

    if (op.empty() || params_path.empty() || in_path.empty() || out_path.empty()) {
        std::cerr << "Usage: homolock_worker --op <total_payroll|avg_salary|total_hours|bonus_pool> "
                  << "--params <params.seal> --relin <relin.seal> --pk <pk.seal> --in <salary.ct|hours.ct> --out <result.ct>\n";
        return 1;
    }

    if (op != "total_payroll" && op != "avg_salary" && op != "total_hours" && op != "bonus_pool") {
        std::cerr << "Unknown op: " << op << "\n";
        return 1;
    }

    // Load parameters and context
    auto parms_buf = read_file(params_path);
    EncryptionParameters parms;
    parms.load(reinterpret_cast<const std::byte*>(parms_buf.data()), parms_buf.size());
    SEALContext seal_ctx(parms);
    {
        std::string err = seal_ctx.parameter_error_message();
        if (!err.empty() && err != "valid") {
            std::cerr << "Parameter error: " << err << "\n";
            return 1;
        }
    }

    // RelinKeys (required by API; not used for add-only but load for consistency)
    if (!relin_path.empty()) {
        auto relin_buf = read_file(relin_path);
        RelinKeys relin_keys;
        relin_keys.load(seal_ctx, reinterpret_cast<const std::byte*>(relin_buf.data()), relin_buf.size());
        (void)relin_keys;
    }

    // Load ciphertexts and sum (no secret key)
    std::vector<Ciphertext> cts = load_ct_vector(in_path, seal_ctx);
    if (cts.empty()) {
        std::cerr << "No ciphertexts in " << in_path << "\n";
        return 1;
    }

    Evaluator evaluator(seal_ctx);
    Ciphertext result;
    if (cts.size() == 1) {
        result = cts[0];
    } else {
        evaluator.add_many(cts, result);
    }

    save_ct(out_path, result);
    std::cout << "Wrote " << out_path << " (sum of " << cts.size() << " ciphertexts)\n";
    return 0;
}
