
## Developer


### Modules

The coturn repository includes different applications and libraries.   The next diagram represents those modules and their dependencies:

```mermaid
---
  config:
    class:
      hideEmptyMembersBox: true
---
classDiagram
   note for relay "turn server process"
   relay --> server
   note for stunclient "STUN test app"
   stunclient --> client
   note for uclient "TURN test/stress app"
   uclient --> common
   uclient --> client
   note for natdiscovery "discover NAT test app"
   natdiscovery --> common
   natdiscovery --> client
   note for peer "fake receiver"
   peer --> client
   note for oauth "create&validate tokens"
   oauth --> common
   oauth --> client
   note for rfc5769_check "run vector tests"
   rfc5769_check --> common

   note for client_cpp "C++ wrapper lib"
   client_cpp  --> client
   relay --> common
   namespace test_apps {
      class stunclient {
      }
      class uclient {
      }
      class natdiscovery {
      }
      class peer {
      }
      class oauth {
      }
      class rfc5769_check  {
      }
   }
```


### Flow chart

![FlowChart](drawio/FlowChart.svg)

### Edit flow chart
- Use [drawio](https://app.diagrams.net/) to edit.

1. Open [drawio](https://app.diagrams.net/) in brower
2. Menu → File → Open from ... → Device:

   Select [FlowChart.html](drawio/FlowChart.html)

3. Edit flow chart
4. Export to svg:

   Menu → File → Export as... → SVG...

