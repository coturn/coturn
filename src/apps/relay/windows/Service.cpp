/*!
 * Service
 * \author Kang Lin <kl222@126.com>
 * \see https://learn.microsoft.com/windows/win32/services/service-program-tasks
 */

#include "Service.h"
#include <AtlBase.h>
#include <AtlConv.h>
#include <fstream>
#include <stdio.h>
#include <tchar.h>
#include <windows.h>

struct WindowsService {
  TCHAR name[MAX_PATH]; // Service name
  fnServiceStart start;
  fnServiceRun run;
  fnServiceStop stop;
  // Current service status handle. don't need close it.
  // See: https://learn.microsoft.com/windows/win32/api/winsvc/nf-winsvc-registerservicectrlhandlera?redirectedfrom=MSDN&devlangs=cpp&f1url=%3FappId%3DDev11IDEF1%26l%3DZH-CN%26k%3Dk(winsvc%252FRegisterServiceCtrlHandler)%3Bk(RegisterServiceCtrlHandler)%3Bk(DevLang-C%252B%252B)%3Bk(TargetOS-Windows)%26rd%3Dtrue
  SERVICE_STATUS_HANDLE  handle;
  HANDLE hEvent;
  SERVICE_STATUS status; // Current service status
};

static WindowsService g_Service;
static std::string g_logFile;

void SetLogFile(const char* pFile) {
    if (pFile)
        g_logFile = pFile;
}

void ServiceLog(char *msg) {
  if (g_logFile.empty()) {
    USES_CONVERSION;
    OutputDebugString(A2T(msg));
  } else {
    std::ofstream ofs(g_logFile, std::ios_base::app);
    if (ofs.is_open()) {
      ofs << "[" << ::GetCurrentProcessId() << ":" << ::GetCurrentThreadId() << "] " << msg << "\n";
      ofs.close();
      return;
    }
  }
}

static fnServiceLog g_Log = ServiceLog;

fnServiceLog SetServiceLog(fnServiceLog log) {
  fnServiceLog oldLog = g_Log;
  if (log)
    g_Log = log;
  else
    g_Log = ServiceLog;
  return oldLog;
}

fnServiceLog GetServiceLog() { return g_Log; }

/*!
 * Allows any thread to log an error message
 * \param lpszFunction - name of function that failed
 * \param dwErr - error code returned from the function
 * \return none
 * \see https://learn.microsoft.com/windows/win32/eventlog/event-logging
 */
void ServiceReportEvent(LPTSTR lpszFunction, DWORD dwErr = NO_ERROR) {
  USES_CONVERSION;

  HANDLE hEventSource = NULL;
  LPCTSTR lpszStrings[1] = {0};
  TCHAR szBuffer[256] = {0};

  hEventSource = RegisterEventSource(NULL, g_Service.name);
  if (hEventSource) {
    WORD wType = EVENTLOG_SUCCESS;
    if (NO_ERROR == dwErr) {
      _stprintf_s(szBuffer, ARRAYSIZE(szBuffer), lpszFunction);
      wType = EVENTLOG_INFORMATION_TYPE;
    } else {
      _stprintf_s(szBuffer, ARRAYSIZE(szBuffer), _T("%s [0x%08X]"), lpszFunction, dwErr);
      wType = EVENTLOG_ERROR_TYPE;
    }
    
    g_Log(T2A(szBuffer));

    lpszStrings[0] = szBuffer;

    BOOL bRet = ReportEvent(hEventSource,                          // Event log handle
                            wType,                                 // Event type
                            0,                                     // Event category
                            0,                                     // Event identifier
                            NULL,                                  // No user security identifier
                            sizeof(lpszStrings) / sizeof(LPCTSTR), // Size of lpszStrings array
                            0,                                     // No binary data
                            lpszStrings,                           // Array of strings
                            NULL);                                 // No binary data
    if (!bRet) {
      TCHAR buf[1024] = {0};
      _stprintf_s(buf, ARRAYSIZE(buf), _T("ReportEvent fail: %s [0x%08X]"), lpszFunction, dwErr);
      g_Log(T2A(buf));
    }
    DeregisterEventSource(hEventSource);
  } else {
    TCHAR buf[1024] = {0};
    _stprintf_s(buf, ARRAYSIZE(buf), _T("%s [0x%08X]"), lpszFunction, dwErr);
    g_Log(T2A(buf));
  }
}

/*!
 * Sets the current service status and reports it to the SCM.
 *
 * \param dwCurrentState - the state of the service (see SERVICE_STATUS)
 * \param dwWin32ExitCode - error code to report
 * \param dwWaitHint - Estimated time for pending operation, in milliseconds
 * \return none
 */
void ServiceReportStatus(DWORD dwCurrentState, DWORD dwWin32ExitCode, DWORD dwWaitHint) {
  static DWORD dwCheckPoint = 1;

  // Fill in the SERVICE_STATUS structure.

  g_Service.status.dwCurrentState = dwCurrentState;
  g_Service.status.dwWin32ExitCode = dwWin32ExitCode;
  g_Service.status.dwWaitHint = dwWaitHint;

  g_Service.status.dwControlsAccepted = (dwCurrentState == SERVICE_START_PENDING) ? 0 : SERVICE_ACCEPT_STOP;

  g_Service.status.dwCheckPoint =
      ((dwCurrentState == SERVICE_RUNNING) || (dwCurrentState == SERVICE_STOPPED)) ? 0 : dwCheckPoint++;

  // Report the status of the service to the SCM.
  SetServiceStatus(g_Service.handle, &g_Service.status);
}

/*!
 * Called by SCM whenever a control code is sent to the service
           using the ControlService function.
 * \param
 * \param dwCtrlCode - type of control requested
 */
void WINAPI ServiceControlHandler(DWORD dwCtrl) {
  // Handle the requested control code.
  switch (dwCtrl) {
  case SERVICE_CONTROL_STOP:
  case SERVICE_CONTROL_SHUTDOWN:
    // SERVICE_STOP_PENDING should be reported before setting the Stop
    ServiceReportStatus(SERVICE_STOP_PENDING, NO_ERROR, 0);
    if (g_Service.stop)
      g_Service.stop();
    ServiceReportStatus(g_Service.status.dwCurrentState, NO_ERROR, 0);
    return;
  case SERVICE_CONTROL_INTERROGATE:
    break;
  default:
    break;
  }
}

/*!
 * Entry point for the service
 * \param dwArgc   - number of command line arguments
 * \param lpszArgv - array of command line arguments
 */
void WINAPI ServiceMain(DWORD dwArgc, LPTSTR lpszArgv[]) {
  USES_CONVERSION;
  g_Log("Enter ServiceMain");

  // Register the handler function for the service
  g_Service.handle = RegisterServiceCtrlHandler(g_Service.name, ServiceControlHandler);
  if (!g_Service.handle) {
    ServiceReportEvent(_T("RegisterServiceCtrlHandler fail"), GetLastError());
    return;
  }

  // These SERVICE_STATUS members remain as set here
  g_Service.status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
  g_Service.status.dwServiceSpecificExitCode = 0;

  // Report initial status to the SCM
  ServiceReportStatus(SERVICE_START_PENDING, NO_ERROR, 3000);

  // Perform service-specific initialization
  if (g_Service.start) {
    char **argv = new char *[dwArgc];
    if (argv) {
      for (DWORD i = 0; i < dwArgc; i++) {
        argv[i] = T2A(lpszArgv[i]);
      }
      DWORD r = g_Service.start(dwArgc, argv);
      delete[] argv;
      if (ERROR_SUCCESS != r) {
        ServiceReportEvent(_T("Service start fail"), r);
        ServiceReportStatus(SERVICE_STOPPED, r, 0);
        return;
      }
    }
  }

  // Report running status when initialization is complete.
  ServiceReportStatus(SERVICE_RUNNING, NO_ERROR, 0);

  // Perform service-specific work.
  if (g_Service.run) {
    DWORD r = g_Service.run();
    if (ERROR_SUCCESS != r) {
      ServiceReportEvent(_T("Service run fail"), r);
      ServiceReportStatus(SERVICE_STOPPED, r, 0);
      return;
    }
  }

  ServiceReportStatus(SERVICE_STOPPED, NO_ERROR, 0);
}

/*!
 * Run service
 * \param name: the name of service
 * \param start: the callback function of start. it maybe NULL
 * \param run: the callback function of run. it maybe NULL
 * \param stop: the callback function of stop. it maybe NULL
 */
int ServiceRun(char *name, fnServiceStart start, fnServiceRun run, fnServiceStop stop) {
  USES_CONVERSION;
  int nRet = 0;

  g_Log("Enter ServiceRun");

  if (!name) {
    g_Log("Error: The name is NULL in ServiceRun");
    return -1;
  }

  ::ZeroMemory(&g_Service, sizeof(g_Service));
  g_Service.start = start;
  g_Service.run = run;
  g_Service.stop = stop;
  if (name) {
    size_t nLen = strlen(name);
    if (nLen > 0)
        _tcsncpy_s(g_Service.name, nLen + 1, A2T(name), nLen);
  }

  // You can add any additional services for the process to this table.
  const SERVICE_TABLE_ENTRY dispatchTable[] = {{g_Service.name, (LPSERVICE_MAIN_FUNCTION)ServiceMain}, {NULL, NULL}};

  // This call returns when the service has stopped.
  // The process should simply terminate when the call returns.
  if (!StartServiceCtrlDispatcher(dispatchTable)) {
    ServiceReportEvent(_T("StartServiceCtrlDispatcher fail"), GetLastError());
    nRet = GetLastError();
  }

  return nRet;
}
