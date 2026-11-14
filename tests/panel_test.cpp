// 面板保留账号规则的单元测试。
//
// 为什么只测这一件事：is_reserved_user 是"运维会不会把自己锁在门外"的唯一
// 守卫，而且它的正确性完全靠一个不显眼的前提 —— auth 层存用户名时会
// trim + lowercase。规则一旦和那个前提脱节，" --del ADMIN " 就能删掉真正的
// admin 账号，而服务还在跑、面板再也进不去。这是纯函数，测起来不花成本。
#include <cstdio>
#include <string>

#include "../src/panel/panel.h"

static int g_failed = 0;

static void expect(bool ok, const char* what) {
    if (ok) {
        std::printf("  ok   %s\n", what);
    } else {
        std::printf("  FAIL %s\n", what);
        ++g_failed;
    }
}

int main() {
    std::printf("[panel] is_reserved_user\n");

    expect(panel::is_reserved_user("admin"), "admin 是保留名");
    // 大小写与空白都要算：auth 层 normalize 就是 trim + lowercase，
    // 不这样做就等于留了一条"看起来不叫 admin，存下去却叫 admin"的通道。
    expect(panel::is_reserved_user("ADMIN"), "ADMIN 是保留名");
    expect(panel::is_reserved_user("Admin"), "Admin 是保留名");
    expect(panel::is_reserved_user("  admin  "), "带空格的 admin 是保留名");
    expect(panel::is_reserved_user("\tAdmin\n"), "带制表/换行的 admin 是保留名");

    expect(!panel::is_reserved_user("alice"), "普通用户名不是保留名");
    expect(!panel::is_reserved_user("administrator"), "administrator 不是保留名");
    expect(!panel::is_reserved_user("admin2"), "admin2 不是保留名");
    expect(!panel::is_reserved_user(""), "空串不是保留名");

    // kAdminUser 与 is_reserved_user 必须同源：如果常量被改成别的名字，
    // 这里会立刻失败，而不是等到运维被锁在门外才发现。
    expect(std::string(panel::kAdminUser) == "admin", "kAdminUser 是 admin");

    if (g_failed == 0) {
        std::printf("[panel] 全部通过\n");
        return 0;
    }
    std::printf("[panel] %d 项失败\n", g_failed);
    return 1;
}
