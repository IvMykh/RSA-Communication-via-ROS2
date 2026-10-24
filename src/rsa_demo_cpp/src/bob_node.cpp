#include <rclcpp/rclcpp.hpp>
#include <std_msgs/msg/string.hpp>
#include "rsa_demo_cpp/crypto_utils.hpp"
#include <unordered_map>
#include <thread>
#include <atomic>
#include <iostream>

using std::placeholders::_1;

class Bob : public rclcpp::Node
{
public:
    Bob() : Node("bob")
    {
        // 1) Keypair
        kp_ = crypto::generate_rsa_keypair(2048);
        if (!kp_)
            throw std::runtime_error("Bob keygen failed");
        key_pub_ = kp_->pub_pem;
        key_priv_ = kp_->priv_pem;

        // 2) Pubs/Subs
        pub_register_ = create_publisher<std_msgs::msg::String>("/key_register", 10);
        pub_lookup_req_ = create_publisher<std_msgs::msg::String>("/key_lookup_req", 10);
        pub_out_ = create_publisher<std_msgs::msg::String>("/channel_alice_bob", 10);

        sub_lookup_resp_ = create_subscription<std_msgs::msg::String>(
            "/key_lookup_resp", 10, std::bind(&Bob::on_lookup_resp, this, _1));

        sub_in_ = create_subscription<std_msgs::msg::String>(
            "/channel_alice_bob", 10, std::bind(&Bob::on_msg, this, _1));

        // 3) Register once (optional PoP)
        {
            std_msgs::msg::String m;
            const std::string payload = std::string("Bob|") + key_pub_;
            crypto::Bytes sig;
            crypto::rsa_sign_pss(key_priv_, crypto::Bytes(payload.begin(), payload.end()), sig);

            m.data = crypto::json_obj({{"name", "Bob"},
                                       {"pub_pem", key_pub_},
                                       {"sig_b64", crypto::b64encode(sig)}});
            pub_register_->publish(m);
        }

        RCLCPP_INFO(
            get_logger(), "Bob ready. Public key SHA-256: %s",
            crypto::sha256_hex(key_pub_).substr(0, 16).c_str());

        RCLCPP_INFO(
            get_logger(),
            "Controls: type a message and press 'Enter' to send it to Alice; '1' to request Alice's key; '0' to exit."
        );

        // 4) Keyboard thread
        input_thread_ = std::thread([this]()
                                    { this->keyboard_loop(); });
    }

    ~Bob()
    {
        stop_flag_ = true;
        if (input_thread_.joinable())
            input_thread_.join();
    }

private:
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

    void on_msg(const std_msgs::msg::String::SharedPtr m)
    {
        std::string sender, cipher_b64, sig_b64;
        if (!crypto::json_get(m->data, "sender", sender))
            return;
        if (!crypto::json_get(m->data, "cipher_b64", cipher_b64))
            return;
        (void)crypto::json_get(m->data, "sig_b64", sig_b64); // optional

        // Only care about Alice
        if (sender != "Alice")
            return;

        // Decrypt first
        crypto::Bytes pt, ct = crypto::b64decode(cipher_b64);
        if (!crypto::rsa_decrypt_oaep(key_priv_, ct, pt))
        {
            RCLCPP_ERROR(get_logger(), "Decrypt failed.");
            return;
        }
        std::string plaintext(pt.begin(), pt.end());

        // Try verify if we have Alice's key; otherwise just warn
        if (!sig_b64.empty() && keys_pub_.count("Alice"))
        {
            crypto::Bytes sig = crypto::b64decode(sig_b64);
            bool ok = crypto::rsa_verify_pss(keys_pub_["Alice"], crypto::Bytes(plaintext.begin(), plaintext.end()), sig);
            if (!ok)
                RCLCPP_WARN(get_logger(), "Signature verification FAILED for message from Alice.");
        }
        else if (!sig_b64.empty() && !keys_pub_.count("Alice"))
        {
            RCLCPP_WARN(
                get_logger(),
                "Message from Alice cannot be verified (Alice's key unknown). Press '1' to request it."
            );
        }

        RCLCPP_INFO(get_logger(), "Alice says: %s", plaintext.c_str());
    }

    void request_alice_key()
    {
        std_msgs::msg::String q;
        q.data = crypto::json_obj({{"name", "Alice"}});
        pub_lookup_req_->publish(q);
        RCLCPP_INFO(get_logger(), "Requested Alice's public key.");
    }

    void send_to_alice(const std::string &plaintext)
    {
        if (!keys_pub_.count("Alice"))
        {
            RCLCPP_WARN(
                get_logger(),
                "Alice's key unknown; not sending. Press '1' to request it."
            );
            return;
        }
        const std::string &alice_pub = keys_pub_["Alice"];

        crypto::Bytes ct;
        if (!crypto::rsa_encrypt_oaep(alice_pub, crypto::Bytes(plaintext.begin(), plaintext.end()), ct))
        {
            RCLCPP_ERROR(get_logger(), "Encrypt failed");
            return;
        }
        crypto::Bytes sig;
        if (!crypto::rsa_sign_pss(key_priv_, crypto::Bytes(plaintext.begin(), plaintext.end()), sig))
        {
            RCLCPP_ERROR(get_logger(), "Sign failed");
            return;
        }

        std_msgs::msg::String msg;
        msg.data = crypto::json_obj({{"sender", "Bob"},
                                     {"receiver", "Alice"},
                                     {"cipher_b64", crypto::b64encode(ct)},
                                     {"sig_b64", crypto::b64encode(sig)}});
        pub_out_->publish(msg);

        RCLCPP_INFO(
            get_logger(),
            "Bob sent an encrypted & signed message to Alice."
        );
    }

    void keyboard_loop()
    {
        while (!stop_flag_)
        {
            std::string input;
            if (!std::getline(std::cin, input))
                break;

            if (input.size() == 1 && input[0] == '1')
            {
                request_alice_key();
                continue;
            }

            if (input.size() == 1 && input[0] == '0')
            {
                stop_flag_ = true;
                continue;
            }

            if (input.size() > 0)
            {
                send_to_alice(input);
            }
        }
    }

    // State
    std::unique_ptr<crypto::KeyPair> kp_;
    std::string key_pub_, key_priv_;
    std::unordered_map<std::string, std::string> keys_pub_;

    // ROS
    rclcpp::Publisher<std_msgs::msg::String>::SharedPtr pub_register_, pub_lookup_req_, pub_out_;
    rclcpp::Subscription<std_msgs::msg::String>::SharedPtr sub_lookup_resp_;
    rclcpp::Subscription<std_msgs::msg::String>::SharedPtr sub_in_;

    // input thread
    std::thread input_thread_;
    std::atomic<bool> stop_flag_{false};
};

int main(int argc, char **argv)
{
    rclcpp::init(argc, argv);
    rclcpp::spin(std::make_shared<Bob>());
    rclcpp::shutdown();
    return 0;
}
