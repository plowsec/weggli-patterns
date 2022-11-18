# weggli-patterns
Collections of patterns for weggli to find nice bugs


## find strcpy-like/memcpy calls with static arrays

```
weggli -R 'func=^str.*cpy$' '{char $b[_]; $func($b, _);}' source

    static char buf[256];

    if ( var1 && obj->a )
    {
        d = obj->a(obj->h);
        if ( e < 300 )
..
      strcpy(someotherbuf,pValue);
    }
    else if(!strcmp("somestring",pParams[i].Name))
    {
      if(pValue != NULL)
      strcpy(buf,pValue);
```



## find strcpy/memcpy calls with length of source input instead of length of destination buffer

```
weggli --unique -R 'func=.*cpy$' '{$func($_, _($a), _($a));}' src                                                                                                                                                                                                                                                  
test.c:371
void some_function(char* conn)
{
..

    strncpy(ps->var[0].value, conn, strlen(conn));
..
    return;
}
```

```
weggli -R 'func=.*cpy$' '{$func($_, $a._, $a._);}' src                                                                                                                                                                                                                                                                                                   
test.c:897
static int stuff(
..
        memcpy(buf, header->value.buf, header->value.length);
..
}
```

## strncpy-like with potential arithmetic errors

```
weggli --unique -R 'func=.*ncpy$' '{$func($_, _($a), $n - $m);}' source

size_t m = strlen(test->user_data);
size_t n = m + (s - test->c) - 5;
strncpy(test->a, test->b, n - m); // n and m are unsigned, if m > n, buffer overflow

```



## malloc-like calls with potential integer overflows

```
weggli -R '$fn=lloc' '{$size; $size=_+_; $fn($size);}' source
weggli -R '$fn=lloc' '{$user_num=atoi(_);$fn($user_num);}' source
```

## unitialized pointers

```
weggli '{ _* $p;NOT: $p = _;$func(&$p);}' source
 
char *name;
int id = a(val[i].parameterName, &name);
 ```
 
 ## format string functions calls' return values to index buffers
 
 ```
weggli -R '$fn=printf$' '{$ret = $fn$($b,_,_);$b[$ret] = _;}' source
 ```
 
 ## no space for zero terminator
 
 `weggli '{$len=strlen($buf);$dest=malloc($len);strcpy($dest,$buf);}' source`
 
 ```
 weggli '{$dest=malloc(strlen($buf));strcpy($dest,$buf);}' test.c                                                                              14:29:41
char *copy;
copy = (char *)malloc(strlen(input));
strcpy(copy, input);
return copy;
```


## format string bugs

`weggli -R '$fn=printf$' -R '$arg=[^"]*' '{$fn($arg);}' test2.c`

This query doesn't work well for format string functions with length specifiers such as snprintf. Here is another one (also not perfect):

```
weggli -R '$fn=^[^n]*printf$' -R '$arg=[^"]*' '{$fn($arg);}' src #for fprintf, printf, etc

weggli -R '$fn=nprintf$' -R '$arg=[^"]*' '{$fn($_,$_,$arg);}' src # for snprintf, etc
```


## integer overflows

```
weggli '{$user_num=atoi(_);$user_num+_;}' source


i = atoi(instanceNumber);
if(i <= 0 || i > objN) return -1;
return i + b;
```

## typical buffer overruns in loops

### Find CVE 2017-9765

```
weggli ' {                                                                                                                                               
    _ $buf[_]; $t = $buf;while (_) { $t; }
}' toto.c


toto.c:1395
static soap_wchar
soap_get_pi(struct soap *soap)
{ char buf[64];
  register char *s = buf;
  register int i = sizeof(buf);
  register soap_wchar c = soap_getchar(soap);
  /* This is a quick way to parse XML PI and we could use a callback instead to
   * enable applications to intercept processing instructions */
  while ((int)c != EOF && c != '?')
  { if (--i > 0)
    { if (soap_blank(c))
        c = ' ';
      *s++ = (char)c;
    }
    c = soap_getchar(soap);
  }
  *s = '\0';
  DBGLOG(TEST, SOAP_MESSAGE(fdebug, "XML PI <?%s?>\n", buf));
..
}
```

## TOCTOU

Needs more function names but you get the idea

```
weggli -R '$f1=(fopen|chmod|access|stat)' -R '$f2=(fopen|chmod|access|stat)' '{$f1($name);$f2($name);}' test3.c                               15:02:42
int main(void) {
char *file_name;
FILE *f_ptr;

/* Initialize file_name */

f_ptr = fopen(file_name, "w");
if (f_ptr == NULL)  {
  /* Handle error */
}

/* ... */

if (chmod(file_name, S_IRUSR) == -1) {
  /* Handle error */
}
}
```



## double free

```
weggli -R '$fn=free' '{$fn($a);not: $a=_;not: return _;$fn($a);}' doublefree.c

int bad_code1() {
    char *var = malloc(sizeof(char) * 10);
    free(var);
    free(var); // <-bug
    return 0;
}
```


## use after free

```
weggli -R '$fn=free' '{$fn($a);not: $a=_;not: return _;_($a);}' use-after-free.c                             


use-after-free.c:8
int bad_code1() {
    NAME *var;
    var = (NAME *)malloc(sizeof(struct name));
    free(var);
    var->func("use after free");
    return 0;
}
```

## find buffers passed as function arguments and freed within the function body

```
weggli '_ $fn(_ $buf) {                                                                                        
    free($buf);
}' source
test.c:930
int parse_stuff(char* Ctx)
{

    test(Ctx, 0, 0, 1);
..
#endif
    }

    //Free allocated memory
    free(Ctx->bufferCtx.pBuf);
    free(Ctx); // <-- 

    return -1;
}
```

Each finding must be analyzed to check if the freed buffer is used by the caller or freed one more time by mistake.


# Original examples

Examples by felixwilhelm

Calls to memcpy that write into a stack-buffer:

```c
weggli '{
    _ $buf[_];
    memcpy($buf,_,_);
}' ./target/src
```

Calls to foo that don't check the return value:
```c
weggli '{
   strict: foo(_);
}' ./target/src
```

Potentially vulnerable snprintf() users:
```c
weggli '{
    $ret = snprintf($b,_,_);
    $b[$ret] = _;
}' ./target/src
```

Potentially uninitialized pointers:
```c
weggli '{ _* $p;
NOT: $p = _;
$func(&$p);
}' ./target/src
```

Potentially insecure WeakPtr usage:
```cpp
weggli --cpp '{
$x = _.GetWeakPtr(); 
DCHECK($x); 
$x->_;}' ./target/src
```

Debug only iterator validation:
```cpp
weggli -X 'DCHECK(_!=_.end());' ./target/src
```

Functions that perform writes into a stack-buffer based on
a function argument. 
```c
weggli '_ $fn(_ $limit) {
    _ $buf[_];
    for (_; $i<$limit; _) {
        $buf[$i]=_;
    }
}' ./target/src
```

Functions with the string decode in their name
```c
weggli -R func=decode '_ $func(_) {_;}'
```

Encoding/Conversion functions
```c
weggli '_ $func($t *$input, $t2 *$output) {
    for (_($i);_;_) {
        $input[$i]=_($output);
    }
}' ./target/src
```

