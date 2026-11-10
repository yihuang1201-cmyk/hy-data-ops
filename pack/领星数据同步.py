#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
领星数据同步.py —— 每天跑一次，把领星近 15 天数据推到「领星 BI 看板」

用法：
    python3 领星数据同步.py            # 正常同步（滚动 15 天覆盖更新）
    python3 领星数据同步.py --dump     # 只拉领星原始数据存到 ./领星原始数据/，不上传（对齐字段用）

首次配置（只改下面 CONFIG 区）：
    1. BOARD_URL     看板公网地址（在看板页面点「发布」后得到，结尾不带 /）
    2. INGEST_TOKEN  看板接收令牌（部署方提供）
    3. APP_ID / APP_SECRET   领星开放平台应用凭证
    4. STORE_NAME    领星店铺 sid → 看板店铺名（如 "美国站"/"欧洲站"），不配置则用领星原名
    5. OWNER_MAP     ASIN/msku → 负责人，领星接口取不到时的兜底（可留空）

依赖：pip3 install requests pycryptodome
特点：幂等（同一天重复跑覆盖更新）、断网/限流自动重试、关机几天再跑自动补齐缺口
"""

import sys
import os
import json
import time
import hashlib
import base64
import datetime as dt
from urllib.parse import quote

import requests

try:
    from Crypto.Cipher import AES
except ImportError:
    sys.exit("缺少依赖，请先执行：pip3 install pycryptodome")

# ============================ CONFIG（只需改这里） ============================

BOARD_URL = ""        # 例：https://xxxxx.site.kimi.team （结尾不带 /）
INGEST_TOKEN = ""     # 看板接收令牌

APP_ID = ""           # 领星开放平台 AppID
APP_SECRET = ""       # 领星开放平台 AppSecret

DAYS = 15             # 滚动覆盖天数（口径已拍板：每天滚动 15 天）

# 领星店铺 sid → 看板显示名；留空 {} 则用领星返回的店铺名
STORE_NAME = {
    # "123456": "美国站",
    # "234567": "欧洲站",
}

# ASIN 或 msku → 负责人（兜底映射，领星接口能取到负责人时优先用接口值）
OWNER_MAP = {
    # "B0XXXXXXX": "陈晨",
}

# 只同步这些店铺（按领星店铺名）；留空 [] = 同步全部店铺
ONLY_STORES = [
    "柏煜-TreeTute-US", "宝银-AluAbi-CA", "宝银-AluAbi-DE", "宝银-AluAbi-ES",
    "宝银-AluAbi-FR", "宝银-AluAbi-UK", "宝银-AluAbi-US", "晟睿-DecorWoo-CA",
    "晟睿-DecorWoo-US", "德睿-DoodleDoo-US", "蒂姆-HAPMARS-CA", "蒂姆-HAPMARS-DE",
    "蒂姆-HAPMARS-ES", "蒂姆-HAPMARS-MX", "蒂姆-HAPMARS-UK", "蒂姆-HAPMARS-US",
    "东进-DailyRest-US", "火映-HAPRAY-IE", "火映-HAPRAY-NL", "火映-HAPRAY-UK",
    "火映-HAPRAY-US", "美宸-Ambesi-DE", "美宸-Ambesi-US", "沐云-WooEnjoy-CA",
    "沐云-WooEnjoy-US",
]

DUMP_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "领星原始数据")

# ---- 凭证独立配置（存在 领星同步配置.py 则覆盖上面 CONFIG，以后更新脚本不用重填）----
_CFG_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "领星同步配置.py")
if os.path.exists(_CFG_FILE):
    import runpy
    _cfg = runpy.run_path(_CFG_FILE)
    BOARD_URL = _cfg.get("BOARD_URL", BOARD_URL)
    INGEST_TOKEN = _cfg.get("INGEST_TOKEN", INGEST_TOKEN)
    APP_ID = _cfg.get("APP_ID", APP_ID)
    APP_SECRET = _cfg.get("APP_SECRET", APP_SECRET)

# ============================ 领星 API 客户端 ============================

LX_BASE = "https://openapi.lingxing.com"


def aes_ecb_encrypt(plain: bytes, key: bytes) -> bytes:
    key = key[:16].ljust(16, b"\0")
    pad = 16 - len(plain) % 16
    plain += bytes([pad]) * pad
    return AES.new(key, AES.MODE_ECB).encrypt(plain)


class LingXing:
    def __init__(self, app_id: str, app_secret: str):
        self.app_id = app_id
        self.app_secret = app_secret
        self.token = None
        self.token_expire = 0

    def _access_token(self):
        if self.token and time.time() < self.token_expire - 300:
            return self.token
        r = requests.post(
            f"{LX_BASE}/api/auth-server/oauth/access-token",
            files={"appId": (None, self.app_id), "appSecret": (None, self.app_secret)},
            timeout=30,
        )
        data = r.json()
        if str(data.get("code")) != "200" and data.get("code") != 200:
            sys.exit(f"领星鉴权失败：{data}")
        self.token = data["data"]["access_token"]
        self.token_expire = time.time() + int(data["data"].get("expires_in", 7200))
        return self.token

    def call(self, path: str, params: dict, version2: bool = False, retries: int = 4):
        """调用业务接口，自动处理签名与限流退避。"""
        token = self._access_token()
        # 官方签名规则（apidoc.lingxing.com/docs/TestSign/signature.html）：
        # 业务参数 + access_token + app_key + timestamp 一起按 ASCII 排序拼 key=value&（空值不参与）
        # → MD5(32位)大写 → AES-128-ECB(密钥=AppId, PKCS7) → Base64
        # 注意：公共参数也参与签名；sign 不要预先 URL 编码，requests 会统一编码一次
        ts = str(int(time.time()))
        all_params = {**params, "access_token": token, "app_key": self.app_id, "timestamp": ts}
        # 数组/对象按 JSON 序列化（紧凑、key 排序）参与签名；布尔用小写 true/false
        def _sv(v):
            if isinstance(v, bool):
                return "true" if v else "false"
            if isinstance(v, (dict, list)):
                return json.dumps(v, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
            return str(v)
        s = "&".join(f"{k}={_sv(all_params[k])}" for k in sorted(all_params)
                     if all_params[k] is not None and all_params[k] != "")
        md5 = hashlib.md5(s.encode()).hexdigest().upper()
        sign = base64.b64encode(aes_ecb_encrypt(md5.encode(), self.app_id.encode())).decode()
        query = {
            "app_key": self.app_id,
            "access_token": token,
            "timestamp": ts,
            "sign": sign,
        }
        headers = {"Authorization": f"Bearer {token}"}
        if version2:
            headers["X-API-VERSION"] = "2"
        for attempt in range(retries):
            r = requests.post(f"{LX_BASE}{path}", params=query, json=params, headers=headers, timeout=60)
            try:
                data = r.json()
            except Exception:
                time.sleep(2)
                continue
            code = data.get("code")
            if code == 0 or code == "0":
                return data.get("data")
            if code in (3001008, "3001008"):  # 限流，退避
                time.sleep(3 + attempt * 3)
                continue
            if code in (3001002, "3001002"):
                sys.exit("当前 IP 不在领星白名单。请换个网络或在领星后台加白名单。")
            if attempt == retries - 1:
                raise RuntimeError(f"{path} 调用失败: code={code} msg={data.get('msg') or data.get('message')}")
            time.sleep(2)
        raise RuntimeError(f"{path} 重试 {retries} 次仍失败")

    def call_paged(self, path: str, params: dict, version2: bool = False,
                   page_size: int = 1000, interval: float = 1.1,
                   list_keys=("list", "records")) -> list:
        """分页拉全量。领星分页接口必须传 offset/length，否则返回空。
        返回结构两种：data={"total":N,"list"/"records":[...]}（产品表现/利润），
        或 data 直接是数组、total 在顶层（广告报表，此时按 len(batch)<page_size 判停）。
        interval=每页间隔秒数（官方限流：串行调用，单店铺间隔1s，多店铺间隔10s）。"""
        rows, offset = [], 0
        while True:
            data = self.call(path, {**params, "offset": offset, "length": page_size},
                             version2=version2)
            if isinstance(data, list):
                batch, total = data, 0
            else:
                batch = []
                for k in list_keys:
                    if isinstance((data or {}).get(k), list):
                        batch = data[k]
                        break
                try:
                    total = int((data or {}).get("total") or 0)
                except (TypeError, ValueError):
                    total = 0
            rows.extend(batch)
            if not batch or len(batch) < page_size or (total and len(rows) >= total):
                break
            offset += len(batch)
            time.sleep(interval)
        return rows

    def profiles_map(self) -> dict:
        """查询广告账号列表（type=seller），返回 sid(str) -> [profile_id(str)]（仅正常状态）。
        appId 无此接口权限时返回 {}，降级为仅 sid 调用。"""
        try:
            data = self.call("/basicOpen/baseData/account/list",
                             {"type": "seller", "offset": 0, "length": 1000})
        except RuntimeError as e:
            print(f"  ⚠ 广告账号列表接口无权限，降级为仅 sid 调用（{e}）")
            return {}
        rows = data if isinstance(data, list) else (data or {}).get("list", [])
        m = {}
        for it in rows or []:
            if it.get("status") == 1 and it.get("sid") and it.get("profile_id"):
                m.setdefault(str(it["sid"]), []).append(str(it["profile_id"]))
        return m


# ============================ 字段映射（候选名，--dump 后按实际对齐） ============================

def pick(obj: dict, candidates, default=None):
    for c in candidates:
        if c in obj and obj[c] is not None:
            return obj[c]
    return default


def num(v, default=0.0):
    try:
        return float(v)
    except (TypeError, ValueError):
        return default


def clean(s, maxlen: int):
    """字符串入库前清洗：去 4 字节字符（emoji 等，MySQL utf8 会拒）+ 截断到列宽。"""
    if s is None:
        return None
    s = "".join(ch for ch in str(s) if ord(ch) <= 0xFFFF).strip()
    return (s[:maxlen] or None)


F_ASIN = ["asin", "asin1", "child_asin"]
F_MSKU = ["msku", "local_sku", "sku"]
F_NAME = ["product_name", "title", "name", "item_name"]
F_BRAND = ["brand", "brand_name"]
F_CAT = ["category_name", "category", "browse_node"]
F_OWNER = ["operator_name", "principal", "person_liable", "owner_name", "developer_name"]
F_LISTED = ["open_date", "listing_date", "on_sale_date", "gmt_create", "create_time"]

F_SALES = ["sales_amount", "total_sales_amount", "salesAmount", "order_amount", "turnover"]
F_UNITS = ["sales_volume", "total_sales_volume", "salesVolume", "units", "order_quantity"]
F_STOCK_DAYS = ["available_days", "sellable_days", "stock_days", "inventory_days"]
F_RATING = ["rating", "average_rating", "star", "stars"]
F_REVIEWS = ["review_count", "reviews", "total_reviews", "comment_count"]
F_RETURN = ["return_rate", "refund_rate"]

F_MARGIN = ["gross_profit", "profit", "total_profit", "grossProfit"]

F_CAMPAIGN_ID = ["campaign_id", "campaignId"]
F_CAMPAIGN = ["campaign_name", "campaignName"]
F_ADGROUP_ID = ["ad_group_id", "adGroupId", "group_id"]
F_ADGROUP = ["ad_group_name", "adGroupName", "group_name"]
F_IMPR = ["impressions", "impression", "exposure"]
F_CLICKS = ["clicks", "click"]
F_SPEND = ["cost", "spend", "ad_cost", "total_cost"]
F_AD_SALES = ["sales", "sales_amount", "total_sales", "attributed_sales", "sales14d"]
F_AD_ORDERS = ["orders", "order_quantity", "conversions", "units", "purchases"]

F_KEYWORD = ["keyword_text", "keywordText", "keyword", "target_text", "targeting"]
F_MATCH = {"EXACT": "精准", "PHRASE": "词组", "BROAD": "广泛", "1": "精准", "2": "词组", "3": "广泛"}


def match_type(v):
    return F_MATCH.get(str(v).upper(), "精准") if v is not None else "精准"


# ============================ 同步流程 ============================

def dates_range(days: int):
    """近 N 天（T-1 起，往前 N 天），从旧到新。"""
    today = dt.date.today()
    return [(today - dt.timedelta(days=i)).isoformat() for i in range(days, 0, -1)]


class Pusher:
    def __init__(self, base: str, token: str):
        self.url = base.rstrip("/") + "/api/ingest"
        self.headers = {"x-ingest-token": token, "Content-Type": "application/json"}
        self.total = 0

    def ping(self):
        r = requests.get(self.url + "/ping", headers=self.headers, timeout=15)
        d = r.json()
        if not d.get("authed"):
            sys.exit(f"看板鉴权失败（检查 BOARD_URL / INGEST_TOKEN）：{d}")
        print("✓ 看板连接正常")

    def push(self, kind: str, rows: list, date: str = None):
        if not rows:
            return
        for i in range(0, len(rows), 4000):  # 接口上限 5000，留余量
            chunk = rows[i:i + 4000]
            body = {"kind": kind, "rows": chunk}
            if date:
                body["date"] = date
            ok = False
            for attempt in range(3):
                try:
                    r = requests.post(self.url, headers=self.headers, json=body, timeout=60)
                    d = r.json()
                    if d.get("code") == 0:
                        self.total += d.get("upserted", 0)
                        ok = True
                        break
                    if attempt == 2:
                        print(f"  ✗ 推送失败 {kind} {date or ''}: {str(d.get('msg'))[:300]}")
                except Exception as e:
                    if attempt == 2:
                        print(f"  ✗ 网络异常 {kind} {date or ''}: {e}")
                time.sleep(3)
            if not ok and len(chunk) > 1:
                # 整批失败 → 逐行推，跳过坏行并打印，不让一颗老鼠屎坏一锅
                print(f"  … {kind} 整批失败，改逐行推送定位坏行")
                for row in chunk:
                    b = {"kind": kind, "rows": [row]}
                    if date:
                        b["date"] = date
                    try:
                        r = requests.post(self.url, headers=self.headers, json=b, timeout=30)
                        d = r.json()
                        if d.get("code") == 0:
                            self.total += d.get("upserted", 0)
                        else:
                            print(f"  ✗ 坏行跳过 {kind} {row.get('store')}/{row.get('asin') or row.get('adGroupId')}: {str(d.get('msg'))[:200]}")
                    except Exception as e:
                        print(f"  ✗ 坏行跳过 {kind}: {e}")


def main():
    dump_only = "--dump" in sys.argv
    if dump_only:
        os.makedirs(DUMP_DIR, exist_ok=True)
        print(f"★ dump 模式：只存原始数据到 {DUMP_DIR}，不上传")

    if not (APP_ID and APP_SECRET):
        sys.exit("请先在脚本顶部 CONFIG 区填 APP_ID / APP_SECRET")
    pusher = None
    if not dump_only:
        if not (BOARD_URL and INGEST_TOKEN):
            sys.exit("请先在脚本顶部 CONFIG 区填 BOARD_URL / INGEST_TOKEN")
        pusher = Pusher(BOARD_URL, INGEST_TOKEN)
        pusher.ping()

    lx = LingXing(APP_ID, APP_SECRET)

    def dump(name, payload):
        if dump_only:
            with open(os.path.join(DUMP_DIR, f"{name}.json"), "w", encoding="utf-8") as f:
                json.dump(payload, f, ensure_ascii=False, indent=2)

    # ---- 1. 店铺列表 ----
    sellers = lx.call("/erp/sc/data/seller/lists", {})
    seller_list = sellers if isinstance(sellers, list) else (sellers or {}).get("list", [])
    dump("sellers", seller_list)
    stores = []
    for s in seller_list:
        sid = str(pick(s, ["sid", "seller_id", "id"], ""))
        if not sid:
            continue
        name = STORE_NAME.get(sid) or pick(s, ["name", "seller_name", "shop_name"], sid)
        if ONLY_STORES and str(name) not in ONLY_STORES:
            continue
        stores.append((sid, str(name)))
    print(f"✓ 店铺 {len(stores)} 个：{'、'.join(n for _, n in stores)}")

    # ---- 2. 产品表现（一次传全部店铺，T-1 单日）→ asin_meta + 字段参考 ----
    # 官方规则：sid 传数组；多店铺调用间隔 10 秒
    all_sids = [int(sid) for sid, _ in stores]
    sid_name = {str(sid): sname for sid, sname in stores}

    def pp_params(day):
        return {"sid": all_sids, "start_date": day, "end_date": day,
                "search_field": "asin", "summary_field": "asin",
                "sort_field": "volume", "sort_type": "desc",
                "is_recently_enum": False, "purchase_status": 0}

    def row_store(it):
        rsid = ""
        for a in (it.get("asins") or []):
            if a.get("sid"):
                rsid = str(a["sid"])
                break
        if not rsid and it.get("sids"):
            rsid = str(it["sids"][0])
        return sid_name.get(rsid, rsid or "未知店铺")

    def row_asin(it):
        for a in (it.get("asins") or []):
            if a.get("asin"):
                return str(a["asin"])
        return pick(it, F_ASIN)

    yesterday = dates_range(1)[0]
    rows = lx.call_paged("/bd/productPerformance/openApi/asinList",
                         pp_params(yesterday), page_size=1000, interval=10.5)
    dump("asinList_sample", rows[:5])  # 存前 5 条看字段
    meta_rows = {}
    for it in rows:
        asin = row_asin(it)
        if not asin:
            continue
        sname = row_store(it)
        msku = None
        local_name = None
        for p in (it.get("price_list") or []):
            if p.get("seller_sku"):
                msku = p["seller_sku"]
                local_name = p.get("local_name") or None
                break
        brand = pick(it, F_BRAND)
        if not brand and it.get("brands"):
            b = it["brands"][0]
            brand = (b.get("brand_name") or b.get("name")) if isinstance(b, dict) else str(b)
        cat = pick(it, F_CAT)
        if not cat and it.get("categories"):
            c = it["categories"][0]
            cat = (c.get("category_name") or c.get("name")) if isinstance(c, dict) else str(c)
        owner = pick(it, F_OWNER)
        if not owner and it.get("principal_names"):
            owner = it["principal_names"][0]
        # 手动标签（tag_set，如「不经营」「经营中」「清货」）；自动标签 auto_tag_set 不采
        tags = [clean(t.get("tag_name"), 64) for t in (it.get("tag_set") or [])
                if isinstance(t, dict) and t.get("tag_name")]
        meta_rows[(sname, asin)] = {
            "store": clean(sname, 128), "asin": clean(asin, 20),
            "name": clean(pick(it, F_NAME, ""), 255) or "",
            "msku": clean(msku or pick(it, F_MSKU), 64),
            "localName": clean(local_name, 128),
            "brand": clean(brand, 128), "category": clean(cat, 128),
            "owner": clean(owner or OWNER_MAP.get(asin) or (OWNER_MAP.get(msku) if msku else None), 64),
            "listedAt": (str(it.get("product_create_time") or pick(it, F_LISTED, "") or "")[:10] or None),
            "tags": [t for t in tags if t],
        }
    if pusher:
        pusher.push("asin_meta", list(meta_rows.values()))
    print(f"✓ 产品档案 {len(meta_rows)} 条")
    time.sleep(10.5)  # 多店铺调用间隔

    # ---- 2.5 广告维度：活动名/广告组名/ASIN 映射（报表只回 ID）----
    camp_name, ag_info, ag_asin = {}, {}, {}
    dim_stores = stores[:2] if dump_only else stores
    prof_map = lx.profiles_map()
    for sid, sname in dim_stores:
        pids = prof_map.get(str(sid)) or [None]
        for pid in pids:
            base = {"sid": int(sid)}
            if pid:
                base["profile_id"] = int(pid)
            for path, handler in (
                ("/pb/openapi/newad/spCampaigns",
                 lambda it: camp_name.__setitem__((str(sid), str(it.get("campaign_id"))), str(it.get("name") or ""))),
                ("/pb/openapi/newad/spAdGroups",
                 lambda it: ag_info.__setitem__((str(sid), str(it.get("ad_group_id"))),
                     {"name": str(it.get("name") or ""), "cid": str(it.get("campaign_id") or "")})),
                ("/pb/openapi/newad/spProductAds",
                 lambda it: ag_asin.setdefault((str(sid), str(it.get("ad_group_id"))), str(it["asin"]))
                     if it.get("asin") else None),
            ):
                try:
                    for it in lx.call_paged(path, dict(base), version2=True,
                                            page_size=1000, interval=1.1):
                        handler(it)
                except RuntimeError as e:
                    print(f"  ⚠ {sname} {path.split('/')[-1]} 拉取失败，跳过（{e}）")
                time.sleep(1.1)
    dump("ad_dim_sample", {"campaigns": dict(list(camp_name.items())[:3]),
                           "adgroups": {str(k): v for k, v in list(ag_info.items())[:3]},
                           "asins": {str(k): v for k, v in list(ag_asin.items())[:3]}})
    print(f"✓ 广告维度：活动 {len(camp_name)} / 广告组 {len(ag_info)} / 商品 {len(ag_asin)}")

    # ---- 3. 逐日：产品表现日指标（多店铺一次拉）+ 广告报表（按店铺）----
    days = dates_range(DAYS)
    if dump_only:
        days = days[:2]  # dump 模式只取 2 天样例，快速对齐字段
    for day in days:
        daily_rows, ad_rows, kw_rows = [], [], []
        # 产品表现日指标：销售额/销量/毛利/广告费/可售天数/评分/评论数/退款率 同出
        prows = lx.call_paged("/bd/productPerformance/openApi/asinList",
                              pp_params(day), page_size=1000, interval=10.5)
        if day == days[0]:
            dump(f"asinList_daily_{day}", prows[:3])
        for it in prows:
            asin = row_asin(it)
            if not asin:
                continue
            daily_rows.append({
                "store": row_store(it), "asin": asin,
                "sales": num(it.get("amount", 0)),
                "units": num(it.get("volume", 0)),
                "margin": num(it.get("gross_profit", 0)),
                "adSpend": num(it.get("spend", 0)),
                "stockDays": int(num(it["available_days"])) if it.get("available_days") is not None else None,
                "rating": num(it.get("avg_star", 0)) or None,
                "reviewCount": int(num(it["reviews_count"])) if it.get("reviews_count") is not None else None,
                "returnRate": num(it.get("return_rate", 0)) or None,
            })
        time.sleep(10.5)  # 多店铺调用间隔

        ad_stores = stores[:2] if dump_only else stores  # dump 模式只取 2 个店铺的广告样例
        for sid, sname in ad_stores:

            # SP 广告组报表（单日；无广告权限/无广告账号的店铺跳过）
            try:
                arows = lx.call_paged("/pb/openapi/newad/spAdGroupReports",
                                      {"sid": int(sid), "report_date": day, "show_detail": 1},
                                      version2=True, page_size=100, interval=1.1)
            except RuntimeError as e:
                print(f"  ⚠ {sname} 广告组报表跳过（{str(e)[:120]}）")
                arows = []
            dump(f"spAdGroup_{sid}_{day}", arows[:3])
            for it in arows:
                gid = pick(it, F_ADGROUP_ID)
                if not gid:
                    continue
                key = (str(sid), str(gid))
                ag = ag_info.get(key, {})
                cid = str(pick(it, F_CAMPAIGN_ID, "") or ag.get("cid", ""))
                ad_rows.append({
                    "store": sname, "asin": ag_asin.get(key, ""),
                    "campaignId": cid,
                    "campaign": camp_name.get((str(sid), cid), ""),
                    "adGroupId": str(gid),
                    "adGroup": ag.get("name", ""),
                    "impressions": int(num(pick(it, F_IMPR, 0))),
                    "clicks": int(num(pick(it, F_CLICKS, 0))),
                    "spend": num(pick(it, F_SPEND, 0)),
                    "sales": num(pick(it, F_AD_SALES, 0)),
                    "orders": int(num(pick(it, F_AD_ORDERS, 0))),
                })

            # SP 关键词报表（单日；同样跳过失败店铺）
            try:
                krows = lx.call_paged("/pb/openapi/newad/spKeywordReports",
                                      {"sid": int(sid), "report_date": day, "show_detail": 1},
                                      version2=True, page_size=100, interval=1.1)
            except RuntimeError as e:
                print(f"  ⚠ {sname} 关键词报表跳过（{str(e)[:120]}）")
                krows = []
            dump(f"spKeyword_{sid}_{day}", krows[:3])
            for it in krows:
                gid = pick(it, F_ADGROUP_ID)
                kw_text = pick(it, F_KEYWORD)
                if not (gid and kw_text):
                    continue
                kw_rows.append({
                    "store": sname, "asin": ag_asin.get((str(sid), str(gid)), ""),
                    "adGroupId": str(gid),
                    "keyword": str(kw_text),
                    "matchType": match_type(pick(it, ["match_type", "matchType"])),
                    "impressions": int(num(pick(it, F_IMPR, 0))),
                    "clicks": int(num(pick(it, F_CLICKS, 0))),
                    "spend": num(pick(it, F_SPEND, 0)),
                    "sales": num(pick(it, F_AD_SALES, 0)),
                    "orders": int(num(pick(it, F_AD_ORDERS, 0))),
                })
            time.sleep(1.1)  # 单店铺调用间隔

        if pusher:
            pusher.push("asin_daily", daily_rows, day)
            pusher.push("adgroup_daily", ad_rows, day)
            pusher.push("keyword_daily", kw_rows, day)
        print(f"✓ {day}  日度 {len(daily_rows)} / 广告组 {len(ad_rows)} / 关键词 {len(kw_rows)}")

    # ---- 4. 订单利润（statistics 3 维度，T-1 滚动重采近 15 天，幂等覆盖）----
    # 实测口径（订单利润探测.py，2026-11-10）：日期必须驼峰 startDate/endDate；
    # 店铺过滤必须 sids 数组（传单 sid 会被静默忽略、返回全部店铺）。
    # 日期字段：asin/msku 维度用 dataDate，seller 维度用 postedDateLocale（只用于校验，落库 date 以采集日为准）。
    PROFIT_DIMS = [
        ("seller", "/bd/profit/statistics/open/seller/list"),
        ("asin",   "/bd/profit/statistics/open/asin/list"),
        ("msku",   "/bd/profit/statistics/open/msku/list"),
    ]
    profit_rows_total, profit_calls, profit_fail = 0, 0, 0
    profit_days = days[:2] if dump_only else days
    for day in profit_days:
        for dim, path in PROFIT_DIMS:
            try:
                prows = lx.call_paged(path, {"sids": all_sids, "startDate": day, "endDate": day},
                                      page_size=1000, interval=10.5)
            except RuntimeError as e:
                profit_fail += 1
                print(f"  ⚠ 订单利润 {dim} {day} 拉取失败（{str(e)[:120]}）")
                continue
            profit_calls += 1
            if day == profit_days[0]:
                dump(f"profit_{dim}_{day}", prows[:3])
            out = []
            for it in prows:
                sname = sid_name.get(str(it.get("sid") or ""), "")
                if not sname:
                    continue
                out.append({
                    "store": clean(sname, 128),
                    "dim": dim,
                    "asin": clean(it.get("asin") or "", 20) or "",
                    "msku": clean(it.get("msku") or it.get("localSku") or "", 64) or "",
                    "currency": clean(it.get("currencyCode"), 8),
                    "listingTagIds": clean(str(it["listingTagIds"]) if it.get("listingTagIds") is not None else None, 255),
                    "sales": num(it.get("totalSalesAmount")),
                    "units": int(num(it.get("totalSalesQuantity"))),
                    "refunds": num(it.get("totalSalesRefunds")),
                    "refundUnits": int(num(it.get("refundsQuantity"))),
                    "platformFee": num(it.get("platformFee")),
                    "fbaDeliveryFee": num(it.get("totalFbaDeliveryFee")),
                    "storageFee": num(it.get("totalStorageFee")),
                    "cgPrice": num(it.get("cgPrice")),
                    "cgTransport": num(it.get("cgTransportCosts")),
                    "adsCost": num(it.get("totalAdsCost")),
                    "adsShared": num(it.get("sharedCostOfAdvertising")),
                    "totalCost": num(it.get("totalCost")),
                    "grossProfit": num(it.get("grossProfit")),
                    "grossRate": num(it.get("grossRate")),
                    "payload": it,  # 全量原始行兜底
                })
            if pusher:
                pusher.push("profit_daily", out, day)
            profit_rows_total += len(out)
            time.sleep(10.5)  # 多店铺调用间隔
    print(f"✓ 订单利润 {profit_rows_total} 行（{profit_calls} 次调用 / {profit_fail} 次失败，"
          f"日期 {profit_days[0] if profit_days else '-'} ~ {profit_days[-1] if profit_days else '-'}，3 维度）")

    if dump_only:
        print(f"★ dump 完成，原始样例已存 {DUMP_DIR}/，把里面每个接口的 json 发给我对齐字段")
    else:
        print(f"★ 同步完成，累计写入 {pusher.total} 行")


if __name__ == "__main__":
    main()
