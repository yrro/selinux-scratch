#include <stdio.h>

#include <unistd.h>
#include <pwd.h>
#include <sys/types.h>

#include <selinux/selinux.h>
#include <selinux/get_context_list.h>

int main() {
	uid_t uid = getuid();
	struct passwd* pw = getpwuid(uid);
	if (pw == NULL) {
		perror("getpwuid");
	}
	printf("user=%s\n", pw->pw_name);

	char* seuser = NULL;
	char* level = NULL;
	if (getseuser(pw->pw_name, "systemd-user", &seuser, &level) != 0) {
		perror("getseuser");
		return 1;
	}
	printf("seuser=%s; level=%s\n", seuser, level);

	static const char fromcon[] = "system_u:system_r:init_t:s0";
	security_context_t* contextlist = NULL;
	int num_contexts = get_ordered_context_list_with_level(seuser, level, (char*)fromcon, &contextlist);
	if (num_contexts == -1) {
		perror("get_ordered_context_list_with_level");
		return 1;
	}

	printf("%d contexts\n", num_contexts);
	if (num_contexts > 0) {
		printf("[0]: %s\n", contextlist[0]);
	}
}
