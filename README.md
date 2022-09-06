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


## find strcpy-like/memcpy calls with static arrays

```
weggli -R 'func=.*cpy$' '{char $b[_]; $func($b, _);}' source

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
 weggli -R 'func=.*cpy$' '{$func($_, $a, strlen($a));}' src                                                                                                                                                                                                                                                                             9:50:37

test.c:371
void some_function(char* conn)
{
..

    strncpy(ps->var[0].value, conn, strlen(conn));
..
    return;
}
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
weggli -R '$fn=free' '{$fn($a);$fn($a);}' doublefree.c

int bad_code1() {
    char *var = malloc(sizeof(char) * 10);
    free(var);
    free(var); // <-bug
    return 0;
}
```


## use after free

```
weggli -R '$fn=free' '{$fn($a);$a;}' use-after-free.c                             


use-after-free.c:8
int bad_code1() {
    NAME *var;
    var = (NAME *)malloc(sizeof(struct name));
    free(var);
    var->func("use after free");
    return 0;
}
```


