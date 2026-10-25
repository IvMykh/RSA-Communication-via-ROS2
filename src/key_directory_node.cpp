#include <rclcpp/rclcpp.hpp>
#include <std_msgs/msg/string.hpp>

#include "rsa_demo_cpp/crypto_utils.hpp"

#include <unordered_map>

using std::placeholders::_1;



class KeyDirectory 
    : public rclcpp::Node
{
public:
    KeyDirectory() 
        : Node("key_directory")
    {
        // Latest snapshot stays available for late subscribers
        auto qos_snapshot = rclcpp::QoS(rclcpp::KeepLast(1)).transient_local();

        pub_keyring_     = create_publisher<std_msgs::msg::String>("/keyring", qos_snapshot);
        pub_lookup_resp_ = create_publisher<std_msgs::msg::String>("/key_lookup_resp", 10);

        sub_register_    = create_subscription<std_msgs::msg::String>(
            "/key_register", 10, 
            std::bind(&KeyDirectory::on_register, this, _1)
        );

        sub_lookup_req_ = create_subscription<std_msgs::msg::String>(
            "/key_lookup_req", 10,
            [this](const std_msgs::msg::String::SharedPtr m) 
                {
                    std::string name;
                    if (!crypto::json_get(m->data, "name", name))
                        return;
                    std::string pem = (keys_.count(name) ? keys_[name] : "");
                    std_msgs::msg::String resp;
                    resp.data = crypto::json_obj({{"name", name}, {"pub_pem", pem}});
                    pub_lookup_resp_->publish(resp);
                }
        );

        RCLCPP_INFO(get_logger(), "KeyDirectory online.");
    }

private:
    void on_register(const std_msgs::msg::String::SharedPtr m)
    {
        std::string name, pem, sig_b64;

        if (!crypto::json_get(m->data, "name", name))
            return;
        if (!crypto::json_get(m->data, "pub_pem", pem))
            return;

        // Optional proof-of-possession: sig over "name|pem" checked with provided pub key.
        bool pop_ok = true;
        if (crypto::json_get(m->data, "sig_b64", sig_b64))
        {
            const std::string payload = name + "|" + pem;
            crypto::Bytes msg(payload.begin(), payload.end());
            crypto::Bytes sig = crypto::b64decode(sig_b64);
            pop_ok = crypto::rsa_verify_pss(pem, msg, sig);
        }
        if (!pop_ok)
        {
            RCLCPP_WARN(get_logger(), "Rejected registration for %s (PoP failed).", name.c_str());
            return;
        }

        const bool is_new = !keys_.count(name);
        const bool changed = !is_new && keys_[name] != pem;
        keys_[name] = pem;

        if (is_new || changed)
        {
            RCLCPP_INFO(get_logger(), "Registered key for %s (sha256=%s)",
                        name.c_str(), crypto::sha256_hex(pem).substr(0, 16).c_str());
            publish_snapshot();
        }
    }

    void publish_snapshot()
    {
        // JSON map of all keys: {"Alice":"PEM...","Bob":"PEM...",...}
        std::string body = "{";
        bool first = true;
        for (auto &kv : keys_)
        {
            if (!first)
                body += ",";
            first = false;
            body += "\"" + kv.first + "\":\"" + crypto::json_escape(kv.second) + "\"";
        }
        body += "}";
        std_msgs::msg::String out;
        out.data = body;
        pub_keyring_->publish(out);
    }

    std::unordered_map<std::string, std::string>                keys_;
    rclcpp::Publisher<std_msgs::msg::String>::SharedPtr         pub_keyring_;
    rclcpp::Publisher<std_msgs::msg::String>::SharedPtr         pub_lookup_resp_;
    rclcpp::Subscription<std_msgs::msg::String>::SharedPtr      sub_register_;
    rclcpp::Subscription<std_msgs::msg::String>::SharedPtr      sub_lookup_req_;
};



int main(int argc, char **argv)
{
    rclcpp::init(argc, argv);
    rclcpp::spin(std::make_shared<KeyDirectory>());
    rclcpp::shutdown();
    return 0;
}
