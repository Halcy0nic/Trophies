# CVEs-for-picoc-3.2.2
Reproduction files for CVE-2022-44312 through CVE-2022-44321

## CVE Reference
* [PicoC v3.2.2 Heap Overflow in the ExpressionCoerceInteger function in expression.c (CVE-2022-44312)](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-44312)
* [PicoC v3.2.2 Heap Overflow in the ExpressionCoerceUnsignedInteger function in expression.c (CVE-2022-44313)](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-44313)
* [PicoC v3.2.2 Heap Overflow in the StringStrncpy function in cstdlib/string.c (CVE-2022-44314)](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-44314)
* [PicoC v3.2.2 Heap Overflow in the ExpressionAssign function in expression.c (CVE-2022-44315)](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-44315)
* [PicoC v3.2.2 Heap Overflow in the LexGetStringConstant function in lex.c (CVE-2022-44316)](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-44316)
* [PicoC v3.2.2 Heap Overflow in the StdioOutPutc function in cstdlib/stdio.c (CVE-2022-44317)](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-44317)
* [PicoC v3.2.2 Heap Overflow in the StringStrcat function in cstdlib/string.c (CVE-2022-44318)](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-44318)
* [PicoC v3.2.2 Heap Overflow in the StdioBasePrintf function in cstdlib/string.c (CVE-2022-44319)](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-44319)
* [PicoC v3.2.2 Heap Overflow in the ExpressionCoerceFP function in expression.c (CVE-2022-44320)](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-44320)
* [PicoC v3.2.2 Heap Overflow in the LexSkipComment function in lex.c (CVE-2022-44321)](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-44321)
* [PicoC v3.2.2 Null Pointer Dereference (CVE-2022-34556)](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-34556)

## Replication

1. Unzip picoc-3.2.2.zip and compile Picoc.
2. Unzip cve-files.zip and run the relevant reproduction file through the interpreter:

```
picoc -s [reproduction_filename.c]
```

