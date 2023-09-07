# README for Type Confusion Extension #

This Burp Extension was created by Certus Cybersecurity to help find type confusion vulnerablities in applications.

### What is type confusion? ###
For more information, please refer to the blogpost, that will be linked here soon.

### What is this extension for? ###

This extension complements Burp's active scanner by substituting integer and booleean JSON values with their string equivalents to check if variable types are being checked on the server's side.

Any JSON body in HTTP request will be re-submitted with the string equivalent:
```
{
    "id":34,
    "name":"John",
    "role":"basic",
    "extended":false
}
```

Will be transformed to:
```
{
    "id":"34",
    "name":"John",
    "role":"basic",
    "extended":false
}
```

If the HTTP response is successful, it would indicate that variable types are not being check on the server side.

### How do I get set up? ###

Ensure you have Jython standalone JAR file attached to Burp and import the extension.py file. 


### Who do I talk to? ###

Use Github issues to raise any problems.
Contributions and feature requests are welcome.
