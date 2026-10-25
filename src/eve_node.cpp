#include <rclcpp/rclcpp.hpp>
#include <std_msgs/msg/string.hpp>
#include "rsa_demo_cpp/crypto_utils.hpp"

#include <unordered_map>
#include <thread>
#include <atomic>
#include <iostream>

using std::placeholders::_1;

class Eve : public rclcpp::Node
{
public:
    Eve() : Node("eve")
    {
        // Generate Eve's keypair, but DO NOT publish it (stay anonymous)
        kp_ = crypto::generate_rsa_keypair(2048);
        if (!kp_)
            throw std::runtime_error("Eve keygen failed");
        priv_pem_ = kp_->priv_pem;
        pub_pem_ = kp_->pub_pem; // unused (kept local)

        // Publishers / Subscribers
        pub_lookup_req_ = create_publisher<std_msgs::msg::String>("/key_lookup_req", 10);
        pub_out_ = create_publisher<std_msgs::msg::String>("/channel_alice_bob", 10);

        sub_lookup_resp_ = create_subscription<std_msgs::msg::String>(
            "/key_lookup_resp", 10, std::bind(&Eve::on_lookup_resp, this, _1));

        sub_in_ = create_subscription<std_msgs::msg::String>(
            "/channel_alice_bob", 10, std::bind(&Eve::on_intercept, this, _1));

        RCLCPP_INFO(
            get_logger(), 
            "Eve is listening on /channel_alice_bob (anonymous)."
        );
        
        RCLCPP_INFO(
            get_logger(), 
            "Controls: type a message to spoof Alice -> Bob; '1' request Bob's key; '0' quit input thread."
        );

        input_thread_ = std::thread([this]()
                                    { keyboard_loop(); });
    }

    ~Eve()
    {
        stop_flag_ = true;
        if (input_thread_.joinable())
            input_thread_.join();
    }

private:
    // --- Subscriptions ---

    void on_lookup_resp(const std_msgs::msg::String::SharedPtr m)
    {
        std::string name, pem;
        if (crypto::json_get(m->data, "name", name) && crypto::json_get(m->data, "pub_pem", pem) && !pem.empty())
        {
            auto it = keys_pub_.find(name);
            bool is_new_or_updated = (it == keys_pub_.end()) || (it->second != pem);
            keys_pub_[name] = pem;
            if (is_new_or_updated)
            {
                RCLCPP_INFO(
                    get_logger(), 
                    "Stored public key for %s (sha256=%s)",
                        name.c_str(), crypto::sha256_hex(pem).substr(0, 16).c_str()
                );
            }
        }
    }

    void on_intercept(const std_msgs::msg::String::SharedPtr m)
    {
        // Print intercepted message metadata; no decryption possible for Eve
        std::string sender, receiver, cipher_b64;
        (void)crypto::json_get(m->data, "sender", sender);
        (void)crypto::json_get(m->data, "receiver", receiver);
        (void)crypto::json_get(m->data, "cipher_b64", cipher_b64);

        const auto size_bytes = crypto::b64decode(cipher_b64).size();
        const std::string digest = cipher_b64.substr(0, 16) + "...";

        RCLCPP_INFO(get_logger(),
                    "[Eve] Intercepted message: sender=%s, receiver=%s, cipher_len=%zu, cipher_b64=%s",
                    sender.empty() ? "?" : sender.c_str(),
                    receiver.empty() ? "?" : receiver.c_str(),
                    size_bytes, digest.c_str());
    }

    // --- Actions ---

    void request_bob_key()
    {
        std_msgs::msg::String q;
        q.data = crypto::json_obj({{"name", "Bob"}});
        pub_lookup_req_->publish(q);
        RCLCPP_INFO(get_logger(), "Requested Bob's public key (anonymously).");
    }

    void send_to_bob_spoofing_alice(const std::string &plaintext)
    {
        if (!keys_pub_.count("Bob"))
        {
            RCLCPP_WARN(
                get_logger(), 
                "Bob's key unknown; not sending. Press '1' to request it."
            );
            return;
        }
        const std::string &bob_pub = keys_pub_["Bob"];

        // Encrypt for Bob
        crypto::Bytes ct;
        if (!crypto::rsa_encrypt_oaep(bob_pub, crypto::Bytes(plaintext.begin(), plaintext.end()), ct))
        {
            RCLCPP_ERROR(get_logger(), "Encrypt failed");
            return;
        }

        // Sign with Eve's private key (but declare sender "Alice") -> Bob's verify will FAIL
        crypto::Bytes sig;
        if (!crypto::rsa_sign_pss(priv_pem_, crypto::Bytes(plaintext.begin(), plaintext.end()), sig))
        {
            RCLCPP_ERROR(get_logger(), "Sign failed");
            return;
        }

        std_msgs::msg::String msg;
        msg.data = crypto::json_obj({{"sender", "Alice"}, // <-- spoofed sender name
                                     {"receiver", "Bob"},
                                     {"cipher_b64", crypto::b64encode(ct)},
                                     {"sig_b64", crypto::b64encode(sig)}});

        pub_out_->publish(msg);
        RCLCPP_INFO(
            get_logger(), 
            "[Eve] Spoofed message sent as 'Alice' to Bob (signature will fail on Bob)."
        );
    }

    // --- Keyboard loop (same UX as yours) ---

    void keyboard_loop()
    {
        while (!stop_flag_)
        {
            std::string input;
            if (!std::getline(std::cin, input))
                break;

            if (input.size() == 1 && input[0] == '1')
            {
                request_bob_key();
                continue;
            }

            if (input.size() == 1 && input[0] == '0')
            {
                stop_flag_ = true;
                continue;
            }

            if (!input.empty())
                send_to_bob_spoofing_alice(input);
        }
    }

    // --- State ---

    std::unique_ptr<crypto::KeyPair> kp_;
    std::string priv_pem_, pub_pem_; // we keep pub key private (no register)

    std::unordered_map<std::string, std::string> keys_pub_; // holds Bob's key if requested

    rclcpp::Publisher<std_msgs::msg::String>::SharedPtr pub_lookup_req_, pub_out_;
    rclcpp::Subscription<std_msgs::msg::String>::SharedPtr sub_lookup_resp_, sub_in_;

    std::thread input_thread_;
    std::atomic<bool> stop_flag_{false};
};



int main(int argc, char **argv)
{
    rclcpp::init(argc, argv);
    rclcpp::spin(std::make_shared<Eve>());
    rclcpp::shutdown();
    return 0;
}
