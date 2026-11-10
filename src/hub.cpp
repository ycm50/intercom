#include "hub.h"

#include <algorithm>

#include "crypto.h"
#include "util.h"

namespace hub {

std::string Hub::pair_key(const std::string &a, const std::string &b) {
  std::string x = a < b ? a : b;
  std::string y = a < b ? b : a;
  std::string joined = "room:" + x + "\x1f" + y;
  return crypto::sha256_hex(joined);
}

void Hub::put_online(const std::shared_ptr<Peer> &peer, std::shared_ptr<Peer> &replaced) {
  replaced.reset();
  std::lock_guard<std::mutex> lk(mu_);
  auto it = user_to_id_.find(peer->user);
  if (it != user_to_id_.end()) {
    auto old = by_id_.find(it->second);
    if (old != by_id_.end()) {
      replaced = old->second;
      std::string old_room = replaced->room;
      if (!old_room.empty()) {
        auto rit = rooms_.find(old_room);
        if (rit != rooms_.end()) {
          auto &ids = rit->second.ids;
          ids.erase(std::remove(ids.begin(), ids.end(), replaced->id), ids.end());
          if (ids.empty()) rooms_.erase(rit);
        }
      }
      by_id_.erase(old);
    }
  }
  by_id_[peer->id] = peer;
  user_to_id_[peer->user] = peer->id;
}

void Hub::remove_online(const std::string &peer_id) {
  std::lock_guard<std::mutex> lk(mu_);
  auto it = by_id_.find(peer_id);
  if (it == by_id_.end()) return;
  leave_room_locked_locked(peer_id);
  user_to_id_.erase(it->second->user);
  by_id_.erase(it);
}

void Hub::leave_room_locked_locked(const std::string &peer_id) {
  auto it = by_id_.find(peer_id);
  if (it == by_id_.end()) return;
  std::string key = it->second->room;
  if (key.empty()) return;
  auto rit = rooms_.find(key);
  if (rit != rooms_.end()) {
    auto &ids = rit->second.ids;
    ids.erase(std::remove(ids.begin(), ids.end(), peer_id), ids.end());
    if (ids.empty()) rooms_.erase(rit);
  }
  it->second->room.clear();
}

std::shared_ptr<Peer> Hub::by_id(const std::string &peer_id) {
  std::lock_guard<std::mutex> lk(mu_);
  auto it = by_id_.find(peer_id);
  return it == by_id_.end() ? nullptr : it->second;
}

std::shared_ptr<Peer> Hub::by_user(const std::string &user) {
  std::lock_guard<std::mutex> lk(mu_);
  auto it = user_to_id_.find(user);
  if (it == user_to_id_.end()) return nullptr;
  auto pit = by_id_.find(it->second);
  return pit == by_id_.end() ? nullptr : pit->second;
}

bool Hub::busy(const std::string &user) {
  std::lock_guard<std::mutex> lk(mu_);
  auto it = user_to_id_.find(user);
  if (it == user_to_id_.end()) return false;
  auto pit = by_id_.find(it->second);
  return pit != by_id_.end() && !pit->second->room.empty();
}

std::vector<OnlineUser> Hub::online() {
  std::lock_guard<std::mutex> lk(mu_);
  std::vector<OnlineUser> out;
  out.reserve(by_id_.size());
  for (const auto &kv : by_id_) {
    OnlineUser u;
    u.user = kv.second->user;
    u.display = kv.second->display;
    u.busy = !kv.second->room.empty();
    out.push_back(u);
  }
  std::sort(out.begin(), out.end(),
            [](const OnlineUser &a, const OnlineUser &b) { return a.user < b.user; });
  return out;
}

std::string Hub::create_room(const std::shared_ptr<Peer> &a, const std::shared_ptr<Peer> &b,
                             const std::string &media) {
  std::lock_guard<std::mutex> lk(mu_);
  if (!a || !b || a->id == b->id) return std::string();
  auto ita = by_id_.find(a->id);
  auto itb = by_id_.find(b->id);
  if (ita == by_id_.end() || itb == by_id_.end()) return std::string();
  if (!ita->second->room.empty() || !itb->second->room.empty()) return std::string();
  std::string key = pair_key(a->user, b->user);
  RoomState st;
  st.ids = {a->id, b->id};
  st.media = media;
  rooms_[key] = st;
  for (auto &p : {a, b}) p->room = key;
  return key;
}

bool Hub::rejoin_room(const std::shared_ptr<Peer> &peer, const std::string &room_key) {
  std::lock_guard<std::mutex> lk(mu_);
  auto rit = rooms_.find(room_key);
  if (rit == rooms_.end()) return false;
  auto it = by_id_.find(peer->id);
  if (it == by_id_.end()) return false;
  auto &ids = rit->second.ids;
  if (std::find(ids.begin(), ids.end(), peer->id) == ids.end()) ids.push_back(peer->id);
  it->second->room = room_key;
  return true;
}

bool Hub::room_exists(const std::string &room_key) {
  std::lock_guard<std::mutex> lk(mu_);
  return rooms_.count(room_key) > 0;
}

std::string Hub::room_media(const std::string &room_key) {
  std::lock_guard<std::mutex> lk(mu_);
  auto it = rooms_.find(room_key);
  return it == rooms_.end() ? std::string() : it->second.media;
}

std::string Hub::room_peer_id(const std::string &room_key, const std::string &except_id) {
  std::lock_guard<std::mutex> lk(mu_);
  auto it = rooms_.find(room_key);
  if (it == rooms_.end()) return std::string();
  for (const auto &id : it->second.ids) {
    if (id != except_id) return id;
  }
  return std::string();
}

void Hub::leave_room(const std::string &peer_id) {
  std::lock_guard<std::mutex> lk(mu_);
  leave_room_locked_locked(peer_id);
}

std::vector<std::shared_ptr<Peer>> Hub::room_peers(const std::string &room_key) {
  std::lock_guard<std::mutex> lk(mu_);
  std::vector<std::shared_ptr<Peer>> out;
  auto it = rooms_.find(room_key);
  if (it == rooms_.end()) return out;
  for (const auto &id : it->second.ids) {
    auto pit = by_id_.find(id);
    if (pit != by_id_.end()) out.push_back(pit->second);
  }
  return out;
}

void Hub::broadcast(const std::string &room_key, const std::string &payload,
                    const std::string &except_id) {
  auto peers = room_peers(room_key);
  for (auto &p : peers) {
    if (!except_id.empty() && p->id == except_id) continue;
    if (p->send) p->send(payload);
  }
}

void Hub::broadcast_all(const std::string &payload, const std::string &except_id) {
  std::vector<std::shared_ptr<Peer>> targets;
  {
    std::lock_guard<std::mutex> lk(mu_);
    for (const auto &kv : by_id_) targets.push_back(kv.second);
  }
  for (auto &p : targets) {
    if (!except_id.empty() && p->id == except_id) continue;
    if (p->send) p->send(payload);
  }
}

void Hub::send_user(const std::string &user, const std::string &payload) {
  auto p = by_user(user);
  if (p && p->send) p->send(payload);
}

size_t Hub::online_count() {
  std::lock_guard<std::mutex> lk(mu_);
  return by_id_.size();
}

size_t Hub::room_count() {
  std::lock_guard<std::mutex> lk(mu_);
  return rooms_.size();
}

}  // namespace hub