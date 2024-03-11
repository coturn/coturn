/*!
 * Example of use service
 * \author Kang Lin <kl222@126.com>
 */

#include "Service.h"
#include "ServiceInstaller.h"
#include <stdio.h>
#include <strsafe.h>
#include <tchar.h>
#include <windows.h>

BOOL g_exit = FALSE;

unsigned long start(int argc, char *argv[]) {
  char msg[1024];
  sprintf_s(msg, 1024, "Start:argc:[%d]:", argc);
  GetServiceLog()(msg);
  for (int i = 0; i < argc; i++) {
    sprintf_s(msg, 1024, " %s", argv[i]);
    GetServiceLog()(msg);
  }
  return 0;
}

unsigned long run() {
  int num = 1;
  GetServiceLog()("run ...");
  do {
    char buf[64];
    sprintf_s(buf, 64, "run %d", num++);
    GetServiceLog()(buf);
    Sleep(1000);
  } while (!g_exit);
  GetServiceLog()("run end");
  return 0;
}

void stop() {
  GetServiceLog()("stop");
  g_exit = TRUE;
}

int main(int argc, char *argv[]) {
  GetServiceLog()("main start");
  if ((argc > 1) && ((*argv[1] == '-' || (*argv[1] == '/')))) {
    if (_stricmp("install", argv[1] + 1) == 0) {
      // Install the service when the command is
      // "-install" or "/install".
      InstallService(_T("coturn"),                     // Name of service
                     _T("coturn"),                     // Name to display
                     SERVICE_AUTO_START,               // Service start type
                     _T(""),                           // Dependencies, format:  "dep1\0dep2\0\0"
                     _T("NT AUTHORITY\\LocalService"), // Service running account(local server)
                     NULL                              // Password of the account
      );
    } else if (_stricmp("remove", argv[1] + 1) == 0) {
      // Uninstall the service when the command is
      // "-remove" or "/remove".
      UninstallService(_T("coturn"));
    } else {
      printf("%s\nUsage:\n%s\n%s", argv[0], "\t-install: install service ", "\t-remove:  remove service");
    }
  } else {
    ServiceRun("coturn", start, run, stop);
  }
  GetServiceLog()("main end");
  return 0;
}
