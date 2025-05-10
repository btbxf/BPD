from ollama import chat
from ollama import ChatResponse
import os
#folder_path = "/root/SPatchD/sp/"

step_A='''
你是开发者，你需要理解补丁的变更和命名语义，分析补丁的目的和意图。
请分析下面这个补丁{Diff}
请逐步思考并提供描述以下特征的分析，最后输出补丁判断结果。
1. **理解变更内容**
   - 描述代码中具体发生了哪些变化，包括新增、修改或删除的部分。
   - 解释这些变化如何影响现有功能或引入新功能。

2. **分析命名语义**
   - 检查函数、类、方法和变量的名称和字符串信息，以理解其用途和上下文。

3. **推测修复目的和意图**
   - 结合命名语义，推断补丁的主要目标是什么，如修复漏洞、改善稳定性或优化性能。
   - 是否修复安全漏洞。

4. **判断补丁类型**
   - 根据变更内容和命名语义，分析补丁是security patch还是non-security patch？请根据补丁对返回值的影响修正结果。
   - 说明理由，解释为什么将其归类于某一特定类型，如是否涉及敏感数据处理、权限控制或漏洞修复。
   
这是所需格式的示例：
-[security patch/non-security patch]:<原因>

Diff=
```
'''

step_B='''
你是开发者，请分析下面这个补丁{Diff}分析补丁是security patch还是non-security patch？ 
这是所需格式的示例：
-[security patch/non-security patch]:<原因>

Diff=
```
'''

Diff = '''

diff --git a/libavformat/http.c b/libavformat/http.c
index d48958d8a3ce0..13f3be4227109 100644
--- a/libavformat/http.c
+++ b/libavformat/http.c
@@ -62,8 +62,8 @@ typedef struct HTTPContext {
     int line_count;
     int http_code;
     /* Used if "Transfer-Encoding: chunked" otherwise -1. */
-    int64_t chunksize;
-    int64_t off, end_off, filesize;
+    uint64_t chunksize;
+    uint64_t off, end_off, filesize;
     char *location;
     HTTPAuthState auth_state;
     HTTPAuthState proxy_auth_state;
@@ -95,9 +95,9 @@ typedef struct HTTPContext {
     AVDictionary *cookie_dict;
     int icy;
     /* how much data was read since the last ICY metadata packet */
-    int icy_data_read;
+    uint64_t icy_data_read;
     /* after how many bytes of read data a new metadata packet will be found */
-    int icy_metaint;
+    uint64_t icy_metaint;
     char *icy_metadata_headers;
     char *icy_metadata_packet;
     AVDictionary *metadata;
@@ -489,7 +489,7 @@ static int http_open(URLContext *h, const char *uri, int flags,
     else
         h->is_streamed = 1;
 
-    s->filesize = -1;
+    s->filesize = UINT64_MAX;
     s->location = av_strdup(uri);
     if (!s->location)
         return AVERROR(ENOMEM);
@@ -616,9 +616,9 @@ static void parse_content_range(URLContext *h, const char *p)
 
     if (!strncmp(p, "bytes ", 6)) {
         p     += 6;
-        s->off = strtoll(p, NULL, 10);
+        s->off = strtoull(p, NULL, 10);
         if ((slash = strchr(p, '/')) && strlen(slash) > 0)
-            s->filesize = strtoll(slash + 1, NULL, 10);
+            s->filesize = strtoull(slash + 1, NULL, 10);
     }
     if (s->seekable == -1 && (!s->is_akamai || s->filesize != 2147483647))
         h->is_streamed = 0; /* we _can_ in fact seek */
@@ -808,8 +808,9 @@ static int process_line(URLContext *h, char *line, int line_count,
             if ((ret = parse_location(s, p)) < 0)
                 return ret;
             *new_location = 1;
-        } else if (!av_strcasecmp(tag, "Content-Length") && s->filesize == -1) {
-            s->filesize = strtoll(p, NULL, 10);
+        } else if (!av_strcasecmp(tag, "Content-Length") &&
+                   s->filesize == UINT64_MAX) {
+            s->filesize = strtoull(p, NULL, 10);
         } else if (!av_strcasecmp(tag, "Content-Range")) {
             parse_content_range(h, p);
         } else if (!av_strcasecmp(tag, "Accept-Ranges") &&
@@ -818,7 +819,7 @@ static int process_line(URLContext *h, char *line, int line_count,
             h->is_streamed = 0;
         } else if (!av_strcasecmp(tag, "Transfer-Encoding") &&
                    !av_strncasecmp(p, "chunked", 7)) {
-            s->filesize  = -1;
+            s->filesize  = UINT64_MAX;
             s->chunksize = 0;
         } else if (!av_strcasecmp(tag, "WWW-Authenticate")) {
             ff_http_auth_handle_header(&s->auth_state, tag, p);
@@ -842,7 +843,7 @@ static int process_line(URLContext *h, char *line, int line_count,
             if (parse_cookie(s, p, &s->cookie_dict))
                 av_log(h, AV_LOG_WARNING, "Unable to parse '%s'\n", p);
         } else if (!av_strcasecmp(tag, "Icy-MetaInt")) {
-            s->icy_metaint = strtoll(p, NULL, 10);
+            s->icy_metaint = strtoull(p, NULL, 10);
         } else if (!av_strncasecmp(tag, "Icy-", 4)) {
             if ((ret = parse_icy(s, tag, p)) < 0)
                 return ret;
@@ -972,7 +973,7 @@ static int http_read_header(URLContext *h, int *new_location)
     char line[MAX_URL_SIZE];
     int err = 0;
 
-    s->chunksize = -1;
+    s->chunksize = UINT64_MAX;
 
     for (;;) {
         if ((err = http_get_line(s, line, sizeof(line))) < 0)
@@ -1006,7 +1007,7 @@ static int http_connect(URLContext *h, const char *path, const char *local_path,
     int post, err;
     char headers[HTTP_HEADERS_SIZE] = "";
     char *authstr = NULL, *proxyauthstr = NULL;
-    int64_t off = s->off;
+    uint64_t off = s->off;
     int len = 0;
     const char *method;
     int send_expect_100 = 0;
@@ -1060,7 +1061,7 @@ static int http_connect(URLContext *h, const char *path, const char *local_path,
     // server supports seeking by analysing the reply headers.
     if (!has_header(s->headers, "\r\nRange: ") && !post && (s->off > 0 || s->end_off || s->seekable == -1)) {
         len += av_strlcatf(headers + len, sizeof(headers) - len,
-                           "Range: bytes=%"PRId64"-", s->off);
+                           "Range: bytes=%"PRIu64"-", s->off);
         if (s->end_off)
             len += av_strlcatf(headers + len, sizeof(headers) - len,
                                "%"PRId64, s->end_off - 1);
@@ -1135,7 +1136,7 @@ static int http_connect(URLContext *h, const char *path, const char *local_path,
     s->line_count       = 0;
     s->off              = 0;
     s->icy_data_read    = 0;
-    s->filesize         = -1;
+    s->filesize         = UINT64_MAX;
     s->willclose        = 0;
     s->end_chunked_post = 0;
     s->end_header       = 0;
@@ -1175,15 +1176,13 @@ static int http_buf_read(URLContext *h, uint8_t *buf, int size)
         memcpy(buf, s->buf_ptr, len);
         s->buf_ptr += len;
     } else {
-        int64_t target_end = s->end_off ? s->end_off : s->filesize;
-        if ((!s->willclose || s->chunksize < 0) &&
-            target_end >= 0 && s->off >= target_end)
+        uint64_t target_end = s->end_off ? s->end_off : s->filesize;
+        if ((!s->willclose || s->chunksize == UINT64_MAX) && s->off >= target_end)
             return AVERROR_EOF;
         len = ffurl_read(s->hd, buf, size);
-        if (!len && (!s->willclose || s->chunksize < 0) &&
-            target_end >= 0 && s->off < target_end) {
+        if (!len && (!s->willclose || s->chunksize == UINT64_MAX) && s->off < target_end) {
             av_log(h, AV_LOG_ERROR,
-                   "Stream ends prematurely at %"PRId64", should be %"PRId64"\n",
+                   "Stream ends prematurely at %"PRIu64", should be %"PRIu64"\n",
                    s->off, target_end
                   );
             return AVERROR(EIO);
@@ -1247,7 +1246,7 @@ static int http_read_stream(URLContext *h, uint8_t *buf, int size)
             return err;
     }
 
-    if (s->chunksize >= 0) {
+    if (s->chunksize != UINT64_MAX) {
         if (!s->chunksize) {
             char line[32];
 
@@ -1256,13 +1255,19 @@ static int http_read_stream(URLContext *h, uint8_t *buf, int size)
                         return err;
                 } while (!*line);    /* skip CR LF from last chunk */
 
-                s->chunksize = strtoll(line, NULL, 16);
+                s->chunksize = strtoull(line, NULL, 16);
 
-                av_log(NULL, AV_LOG_TRACE, "Chunked encoding data size: %"PRId64"'\n",
+                av_log(h, AV_LOG_TRACE,
+                       "Chunked encoding data size: %"PRIu64"'\n",
                         s->chunksize);
 
                 if (!s->chunksize)
                     return 0;
+                else if (s->chunksize == UINT64_MAX) {
+                    av_log(h, AV_LOG_ERROR, "Invalid chunk size %"PRIu64"\n",
+                           s->chunksize);
+                    return AVERROR(EINVAL);
+                }
         }
         size = FFMIN(size, s->chunksize);
     }
@@ -1273,17 +1278,17 @@ static int http_read_stream(URLContext *h, uint8_t *buf, int size)
     read_ret = http_buf_read(h, buf, size);
     if (   (read_ret  < 0 && s->reconnect        && (!h->is_streamed || s->reconnect_streamed) && s->filesize > 0 && s->off < s->filesize)
         || (read_ret == 0 && s->reconnect_at_eof && (!h->is_streamed || s->reconnect_streamed))) {
-        int64_t target = h->is_streamed ? 0 : s->off;
+        uint64_t target = h->is_streamed ? 0 : s->off;
 
         if (s->reconnect_delay > s->reconnect_delay_max)
             return AVERROR(EIO);
 
-        av_log(h, AV_LOG_INFO, "Will reconnect at %"PRId64" error=%s.\n", s->off, av_err2str(read_ret));
+        av_log(h, AV_LOG_INFO, "Will reconnect at %"PRIu64" error=%s.\n", s->off, av_err2str(read_ret));
         av_usleep(1000U*1000*s->reconnect_delay);
         s->reconnect_delay = 1 + 2*s->reconnect_delay;
         seek_ret = http_seek_internal(h, target, SEEK_SET, 1);
         if (seek_ret != target) {
-            av_log(h, AV_LOG_ERROR, "Failed to reconnect at %"PRId64".\n", target);
+            av_log(h, AV_LOG_ERROR, "Failed to reconnect at %"PRIu64".\n", target);
             return read_ret;
         }
 
@@ -1338,10 +1343,11 @@ static int store_icy(URLContext *h, int size)
 {
     HTTPContext *s = h->priv_data;
     /* until next metadata packet */
-    int remaining = s->icy_metaint - s->icy_data_read;
+    uint64_t remaining;
 
-    if (remaining < 0)
+    if (s->icy_metaint < s->icy_data_read)
         return AVERROR_INVALIDDATA;
+    remaining = s->icy_metaint - s->icy_data_read;
 
     if (!remaining) {
         /* The metadata packet is variable sized. It has a 1 byte header
@@ -1455,7 +1461,7 @@ static int64_t http_seek_internal(URLContext *h, int64_t off, int whence, int fo
 {
     HTTPContext *s = h->priv_data;
     URLContext *old_hd = s->hd;
-    int64_t old_off = s->off;
+    uint64_t old_off = s->off;
     uint8_t old_buf[BUFFER_SIZE];
     int old_buf_size, ret;
     AVDictionary *options = NULL;
@@ -1466,7 +1472,7 @@ static int64_t http_seek_internal(URLContext *h, int64_t off, int whence, int fo
              ((whence == SEEK_CUR && off == 0) ||
               (whence == SEEK_SET && off == s->off)))
         return s->off;
-    else if ((s->filesize == -1 && whence == SEEK_END))
+    else if ((s->filesize == UINT64_MAX && whence == SEEK_END))
         return AVERROR(ENOSYS);
 
     if (whence == SEEK_CUR)
@@ -1621,7 +1627,7 @@ static int http_proxy_open(URLContext *h, const char *uri, int flags)
     s->buf_ptr    = s->buffer;
     s->buf_end    = s->buffer;
     s->line_count = 0;
-    s->filesize   = -1;
+    s->filesize   = UINT64_MAX;
     cur_auth_type = s->proxy_auth_state.auth_type;
 
     /* Note: This uses buffering, potentially reading more than the
'''

# 定义多轮对话
def multi_round_chat(code):
    # 第一步：理解变更内容
    print()
    step_A_with_context = f"{step_B}\nDiff: {code}"
    response_A = chat(
        model='deepseek-R1:70b', 
        messages=[{'role': 'user', 'content': step_A_with_context}],
        stream=False,
        options={'temperature': 0.7}
    )
    context_A = response_A['message']['content']
    context_A_1 = context_A[context_A.index('</think>')+len('</think>')+1:]
    print(f"- [补丁]: {context_A_1}")
    #print()

    
    
      
    

# 执行多轮对话
n=0
# 遍历文件夹中的所有文件
'''
for filename in os.listdir(folder_path):
    file_path = os.path.join(folder_path, filename)
    
    # 只处理文件
    if os.path.isfile(file_path):
        with open(file_path, 'r', encoding='utf-8') as file:
            #code = file.read()
            lines = file.readlines()

            # 从 diff 开始的部分提取内容
            diff_started = False
            code = ""
            
            for line in lines:
                if line.startswith("diff"):  # 标识 diff 开始
                    diff_started = True
                if diff_started:  # 只读取 diff 之后的部分
                    code += line
            print(n)
            print(f"Response for {filename}:")
            print()
            n=n+1
            multi_round_chat(code)

'''
multi_round_chat(Diff)
