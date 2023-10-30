#include <iostream>
#include <string>
#include <jwt-cpp/jwt.h>
#include <httplib.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

std::string bignum_to_raw_string(const BIGNUM *bn)
{
    int bn_size = BN_num_bytes(bn);
    std::string raw(bn_size, 0);
    BN_bn2bin(bn, reinterpret_cast<unsigned char *>(&raw[0]));
    return raw;
}

std::string extract_pub_key(EVP_PKEY *pkey)
{
    BIO *bio = BIO_new(BIO_s_mem());
    PEM_write_bio_PUBKEY(bio, pkey);
    char *data = NULL;
    long len = BIO_get_mem_data(bio, &data);
    std::string result(data, len);
    BIO_free(bio);
    return result;
}

std::string extract_priv_key(EVP_PKEY *pkey)
{
    BIO *bio = BIO_new(BIO_s_mem());
    PEM_write_bio_PrivateKey(bio, pkey, NULL, NULL, 0, NULL, NULL);
    char *data = NULL;
    long len = BIO_get_mem_data(bio, &data);
    std::string result(data, len);
    BIO_free(bio);
    return result;
}

std::string base64_url_encode(const std::string &data)
{
    static const std::string base64_chars =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz"
        "0123456789+/";

    std::string ret;
    int i = 0;
    int j = 0;
    unsigned char char_array_3[3];
    unsigned char char_array_4[4];

    for (size_t n = 0; n < data.size(); n++)
    {
        char_array_3[i++] = data[n];
        if (i == 3)
        {
            char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
            char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
            char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
            char_array_4[3] = char_array_3[2] & 0x3f;

            for (i = 0; (i < 4); i++)
                ret += base64_chars[char_array_4[i]];
            i = 0;
        }
    }

    if (i)
    {
        for (j = i; j < 3; j++)
            char_array_3[j] = '\0';

        char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
        char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
        char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
        char_array_4[3] = char_array_3[2] & 0x3f;

        for (j = 0; (j < i + 1); j++)
            ret += base64_chars[char_array_4[j]];
    }

    // Replace '+' with '-', '/' with '_' and remove '='
    std::replace(ret.begin(), ret.end(), '+', '-');
    std::replace(ret.begin(), ret.end(), '/', '_');
    ret.erase(std::remove(ret.begin(), ret.end(), '='), ret.end());

    return ret;
}

class Database {
public:
    Database(const std::string &filename)
    {
        if (sqlite3_open(filename.c_str(), &db))
        {
            std::cerr << "Can't open database: " << sqlite3_errmsg(db) << std::endl;
            exit(1);
        }
        const char *sql = "CREATE TABLE IF NOT EXISTS keys ("
                          "kid INTEGER PRIMARY KEY AUTOINCREMENT,"
                          "key BLOB NOT NULL,"
                          "exp INTEGER NOT NULL);";
        char *errmsg;
        if (sqlite3_exec(db, sql, 0, 0, &errmsg) != SQLITE_OK)
        {
            std::cerr << "SQL error: " << errmsg << std::endl;
            sqlite3_free(errmsg);
            exit(1);
        }
    }

    ~Database()
    {
        sqlite3_close(db);
    }

    void save_key(const std::string &key, int exp)
    {
        std::string sql = "INSERT INTO keys (key, exp) VALUES (?, ?);";
        sqlite3_stmt *stmt;
        if (sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, 0) != SQLITE_OK)
        {
            std::cerr << "SQL error: " << sqlite3_errmsg(db) << std::endl;
            exit(1);
        }
        sqlite3_bind_blob(stmt, 1, key.c_str(), key.size(), SQLITE_STATIC);
        sqlite3_bind_int(stmt, 2, exp);
        if (sqlite3_step(stmt) != SQLITE_DONE)
        {
            std::cerr << "SQL error: " << sqlite3_errmsg(db) << std::endl;
            exit(1);
        }
        sqlite3_finalize(stmt);
    }

    std::vector<std::pair<std::string, std::string>> get_valid_keys()
    {
        std::vector<std::pair<std::string, std::string>> keys;
        std::string sql = "SELECT kid, key FROM keys WHERE exp > ?;";
        sqlite3_stmt *stmt;
        if (sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, 0) != SQLITE_OK)
        {
            std::cerr << "SQL error: " << sqlite3_errmsg(db) << std::endl;
            exit(1);
        }
        sqlite3_bind_int(stmt, 1, std::time(nullptr));
        while (sqlite3_step(stmt) == SQLITE_ROW)
        {
            int kid = sqlite3_column_int(stmt, 0);
            const void *key_data = sqlite3_column_blob(stmt, 1);
            int key_size = sqlite3_column_bytes(stmt, 1);
            std::string key(static_cast<const char *>(key_data), key_size);
            keys.emplace_back(std::to_string(kid), key);
        }
        sqlite3_finalize(stmt);
        return keys;
    }

    std::string get_key(bool expired)
    {
        std::string sql = "SELECT key FROM keys WHERE exp " + std::string(expired ? "<=" : ">") + " ? LIMIT 1;";
        sqlite3_stmt *stmt;
        if (sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, 0) != SQLITE_OK)
        {
            std::cerr << "SQL error: " << sqlite3_errmsg(db) << std::endl;
            exit(1);
        }
        sqlite3_bind_int(stmt, 1, std::time(nullptr));
        if (sqlite3_step(stmt) == SQLITE_ROW)
        {
            const void *key_data = sqlite3_column_blob(stmt, 0);
            int key_size = sqlite3_column_bytes(stmt, 0);
            std::string key(static_cast<const char *>(key_data), key_size);
            sqlite3_finalize(stmt);
            return key;
        }
        else
        {
            sqlite3_finalize(stmt);
            return "";
        }
    }

private:
    sqlite3 *db;
};

int main()
{
    // Initialize database
    Database db("totally_not_my_privateKeys.db");

    // Generate RSA key pair
    EVP_PKEY *pkey = EVP_PKEY_new();
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    EVP_PKEY_keygen_init(ctx);
    EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048);
    EVP_PKEY_keygen(ctx, &pkey);
    EVP_PKEY_CTX_free(ctx);

    // Extract private key and save to database
    std::string priv_key = extract_priv_key(pkey);
    db.save_key(priv_key, std::time(nullptr) + 3600); // Expires in 1 hour
    db.save_key(priv_key, std::time(nullptr) - 1); // Expired

    // Start HTTP server
    httplib::Server svr;

    svr.Post("/auth", [&](const httplib::Request &req, httplib::Response &res)
             {
                 if (req.method != "POST")
                 {
                     res.status = 405; // Method Not Allowed
                     res.set_content("Method Not Allowed", "text/plain");
                     return;
                 }
                 // Check if the "expired" query parameter is set to "true"
                 bool expired = req.has_param("expired") && req.get_param_value("expired") == "true";

                 // Read private key from DB
                 std::string priv_key = db.get_key(expired);
                 if (priv_key.empty())
                 {
                     res.status = 404; // Not Found
                     res.set_content("No suitable key found", "text/plain");
                     return;
                 }

                 // Extract public key
                 std::string pub_key = extract_pub_key(pkey);

                 // Create JWT token
                 auto now = std::chrono::system_clock::now();
                 auto token = jwt::create()
                                   .set_issuer("auth0")
                                   .set_type("JWT")
                                   .set_payload_claim("sample", jwt::claim(std::string("test")))
                                   .set_issued_at(std::chrono::system_clock::now())
                                   .set_expires_at(expired ? now - std::chrono::seconds{1} : now + std::chrono::hours{24})
                                   .set_key_id(expired ? "expiredKID" : "goodKID")
                                   .sign(jwt::algorithm::rs256(pub_key, priv_key, "", ""));

                 res.set_content(token, "text/plain");
             });

    svr.listen("localhost", 8080);

    // Clean up
    EVP_PKEY_free(pkey);
}