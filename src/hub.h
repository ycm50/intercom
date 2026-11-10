#pragma once
// 在线状态与 1:1 房间。所有状态仅在内存，进程退出即消失。
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

namespace hub {

struct Peer {
  std::string id;
  std::string user;     // 账号（小写）
  std::string display;  // 展示名
  std::string room;     // 当前房间键，空表示不在会话中
  int64_t joined_at = 0;

  // 由 WebSocket 处理线程设置
  std::function<bool(const std::string &)> send;
  std::function<void(uint16_t, const std::string &)> close;
};

struct OnlineUser {
  std::string user;
  std::string display;
  bool busy = false;
};

class Hub {
 public:
  // 两人房间键：对账号排序后做 sha256
  static std::string pair_key(const std::string &a, const std::string &b);

  // 上线；若同名账号已有连接，返回旧连接（由调用方决定如何踢掉）
  void put_online(const std::shared_ptr<Peer> &peer, std::shared_ptr<Peer> &replaced);
  void remove_online(const std::string &peer_id);

  std::shared_ptr<Peer> by_id(const std::string &peer_id);
  std::shared_ptr<Peer> by_user(const std::string &user);
  bool busy(const std::string &user);
  std::vector<OnlineUser> online();

  // 建立 1:1 房间，成功返回房间键，失败返回空串
  std::string create_room(const std::shared_ptr<Peer> &a, const std::shared_ptr<Peer> &b,
                          const std::string &media);
  // 掉线重连后把连接重新挂回原来的房间（房间在人没回来前一直保留）
  bool rejoin_room(const std::shared_ptr<Peer> &peer, const std::string &room_key);
  bool room_exists(const std::string &room_key);
  std::string room_media(const std::string &room_key);
  std::string room_peer_id(const std::string &room_key, const std::string &except_id);
  void leave_room(const std::string &peer_id);
  std::vector<std::shared_ptr<Peer>> room_peers(const std::string &room_key);

  void broadcast(const std::string &room_key, const std::string &payload,
                 const std::string &except_id = std::string());
  void broadcast_all(const std::string &payload, const std::string &except_id = std::string());
  void send_user(const std::string &user, const std::string &payload);

  size_t online_count();
  size_t room_count();

 private:
  void leave_room_locked_locked(const std::string &peer_id);

  std::mutex mu_;
  std::unordered_map<std::string, std::shared_ptr<Peer>> by_id_;
  std::unordered_map<std::string, std::string> user_to_id_;
  struct RoomState {
    std::vector<std::string> ids;
    std::string media;
  };
  std::unordered_map<std::string, RoomState> rooms_;
};

}  // namespace hub