# Awesome_IoC_Regex

## URL
```python
r'\b(https?[:\.]\/\/(?:www\.|(?!www))[a-zA-Z0-9][a-zA-Z0-9-]+[a-zA-Z0-9]\.[^\s]{2,}|www?\.[a-zA-Z0-9][a-zA-Z0-9-]+[a-zA-Z0-9]\.[^\s]{2,}|https?[:\.]\/\/(?:www\.|(?!www))[a-zA-Z0-9]+\.[^\s]{2,}|www\.[a-zA-Z0-9]+)\b'

r'\b(http[:\.]\/\/www\.|https[:\.]\/\/www\.|http[:\.]\/\/|https[:\.]\/\/|ftp[:\.]\/\/|wss[:\.]\/\/)?[a-z0-9]+([\-\.]{1}[a-z0-9]+)+\.[a-z]{2,}(:[0-9]{1,5})?\/([^,\s]+)?'

r'\bhttps?[:\.]\/\/(?:www\.|(?!www)).+\/+\.*[^\s]*\b'

r"((http|https)://)(www.)?[a-zA-Z0-9@:%._\\+~#?&//=]{2,256}\.[a-z]{2,6}\b([-a-zA-Z0-9@:%._\\+~#?&//=]*)"
```
## Filepath
```python
r'\b(?<!\w)(~)?((\\|/){1,2}(\w+)|([a-zA-Z]:))((((\\|/){1,4}[\w\.\-]+)\$?){1,})\b'
```
## IPAddress
```python
r"(\d+\.\d+\.\d+\.\d+\Z)"
r'\b([0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}|(\d{1,3}\.){3}\d{1,3}\b'
```
## Email
```python
r'\b[a-zA-Z0-9_\-\.]+@[a-zA-Z0-9_\-\.]+\.[a-zA-Z]{2,5}\b'

r"^\w+([-+.]\w+)*@\w+([-.]\w+)*\.\w+([-.]\w+)*$"
```
## CVE_ID
```python
r'\b(?i)cve-\d{4}-\d{4,7}\b'
```
## Filename
```python
r'\b[A-Za-z0-9-_\.]+\.(txt|php|exe|dll|bat|sh|sys|htm|html|js|jar|jpg|png|vb|scr|pif|chm|zip|rar|cab|pds|docx|doc|ppt|pptx|xls|xlsx|swf|gif|ps|tmp|lnk)'
```
## Domain
```python
r'\b(?:[a-z0-9][\w\-]*[a-z0-9]*\.)*(?:(?:(?:[a-z0-9][\w\-]*[a-z0-9]*)(?:\.[a-z0-9]+)?)|(?:(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)))\b'

r"^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}$"
```
## Hash
```python
r'[a-f0-9]{64}|[A-F0-9]{64}'

r'[a-f0-9]{40}|[A-F0-9]{40}'

r'[a-f0-9]{32}|[A-F0-9]{32}'

r'^(((([a-z,1-9]+)|[0-9,A-Z]+))([^a-z\.]))*'

```

## Usage
Example
```python
def determine_ioc_type(ioc):
    patterns = {
        "ip": r"(\d+\.\d+\.\d+\.\d+\Z)",
        "email": r"^\w+([-+.]\w+)*@\w+([-.]\w+)*\.\w+([-.]\w+)*$",
        "domain": r"^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}$",
        "hash": r"^(((([a-z,1-9]+)|[0-9,A-Z]+))([^a-z\.]))*",
        "url": r"((http|https)://)(www.)?[a-zA-Z0-9@:%._\\+~#?&//=]{2,256}\.[a-z]{2,6}\b([-a-zA-Z0-9@:%._\\+~#?&//=]*)"
    }

    for ioc_type, pattern in patterns.items():
        if re.fullmatch(pattern, ioc):
            return ioc_type
    return None
```


## Note
#### Online Test Tool
https://regex101.com/

#### Regex Library 
https://regexlib.com/?AspxAutoDetectCookieSupport=1