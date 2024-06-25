# Asm-qsg

# Heading 1&#x20;

## Heading 2

### Heading 3

test image - drop in image without adding to image folder first

![alt text](https://archbee-image-uploads.s3.amazonaws.com/x-S9gkIA8olpyprsqa11G/zefK73m1PuS402NvudsaH_screenshot-2024-06-17-at-85541-am.png "caption")

test image - added to the image folder first

[]()



test image - drag and drop from image folder

does not work



test image - drag and drop from desktop

works

![](https://archbee-image-uploads.s3.amazonaws.com/x-S9gkIA8olpyprsqa11G/eEgcpkv50AhqLtGpO_z_k_screenshot-2024-06-18-at-14434-pm.png)



:::hint{type="info"}
# heading 1

sample text

- bullet 1
- bullet 2
:::

:::hint{type="success"}
## heading 2

sample text

1. list item 1
2. list item 2
:::

:::hint{type="warning"}
### heading 3

[test link](https://miro.com/app/board/uXjVK8A_FFI=/)
:::

:::hint{type="danger"}
**boldface**

> test

`test`

test

- [ ] [checklist](https://miro.com/app/board/uXjVK8A_FFI=/)
- [ ] checklist
:::



```json
{
  "config": {
    "name": "Linux Agent",
    "endpoint": "<region-code>.data.logs.insight.rapid7.com",
    "region": "<region-code>",
    "api-key": "<platform-api-key>",
    "state-file": "/opt/rapid7/ir_agent/components/insight_agent/common/config/logs.state",
    "logs": [
      {
        "name": "Syslog",
        "destination": "Linux Logs/Syslog",
        "path": "/var/log/syslog",
        "enabled": true
      },
      {
        "name": "Audit log",
        "destination": "Linux Logs/audit.log",
        "path": "/var/log/audit/audit.log",
        "enabled": true
      },
      {
        "name": "My Log Name",
        "destination": "Enter Desired Log Set Name Here/Enter Desired Log Name Here",
        "path": "/path/to/log/file.log",
        "enabled": true
      }
    ]
  }
}
```

```powershell
blah
blah
blah
```



## expandable content testing

## code snippet testing











