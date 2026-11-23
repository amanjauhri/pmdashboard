#!/usr/bin/env python3
"""Build the password-locked PM Dashboard page.

Usage:
  build.py init --password PW          -> writes build/keywrap.json, prints the content key (hex). Run once.
  build.py build --raw DIR --key HEX --out index.html [--name Aman] [--today YYYY-MM-DD]

--raw DIR holds whatever was fetched this morning (any file may be missing):
  fold_cur.json, fold_prev.json   list_transactions answers ({"transactions":[...]}) for this and last month
  kite_holdings.json              Kite portfolio mode=holdings type=full answer ({"data":[...]})
  kite_summary.json               Kite portfolio mode=holdings type=summary answer
  fold_cards.json                 Fold list_credit_cards answer ({"credit_cards":[...]})
  kite_mf.json                    Kite mutual_funds mode=holdings answer (list)
  history.json                    list of snapshots {date, stocks_value, stocks_invested, mf_value, mf_invested}
  brief.json, news.json           the dashboard's daily_brief / ai_news files ({"rows":[...]})
Plaintext never leaves this machine: only the encrypted blob is written into index.html.
"""
import argparse, base64, calendar, datetime as dt, json, os, re, secrets, sys
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

HERE = os.path.dirname(os.path.abspath(__file__))
EXCL = {"Untagged", "Credit Bill", "Investment"}
IST = dt.timezone(dt.timedelta(hours=5, minutes=30))
b64 = lambda b: base64.b64encode(b).decode()


def load(raw, name):
    p = os.path.join(raw, name)
    if not os.path.exists(p):
        return None
    try:
        with open(p) as f:
            return json.load(f)
    except Exception:
        return None


def txns(obj):
    if isinstance(obj, dict) and isinstance(obj.get("transactions"), list):
        return obj["transactions"]
    if isinstance(obj, list):
        return obj
    return None


def ist_day(iso):
    t = dt.datetime.fromisoformat(iso.replace("Z", "+00:00")).astimezone(IST)
    return t.date().isoformat()


CARD_BILL = re.compile(r"BILLPAY|CC BILL|CREDIT ?CARD|CRED CLUB|CHEQ", re.I)


def cat_of(t):
    c = (t.get("category") or {}).get("name") or "Untagged"
    if c == "Bill" and CARD_BILL.search(t.get("narration") or ""):
        return "Credit Bill"
    return c


def amt(t):
    return float(t.get("effective_amount") or t.get("amount") or 0)


def spends(rows):
    for t in rows or []:
        if (t.get("type") or "DEBIT").upper() != "DEBIT" or t.get("excluded_from_cash_flow"):
            continue
        if cat_of(t) in EXCL:
            continue
        yield t


def merchant(t):
    m = t.get("merchant_name")
    if m:
        return m.strip().title() if (m.isupper() or m.islower()) else m.strip()
    n = (t.get("narration") or "").split("/")
    return (n[1].strip().title() if len(n) > 1 and n[1].strip() else "Other")


def cat_totals(rows):
    out = {}
    for t in rows or []:
        if (t.get("type") or "DEBIT").upper() != "DEBIT" or t.get("excluded_from_cash_flow"):
            continue
        c = cat_of(t)
        out[c] = out.get(c, 0) + amt(t)
    return out


def top_merchants(rows, cat, n=3):
    m = {}
    for t in spends(rows):
        if cat_of(t) == cat:
            k = merchant(t)
            a = m.setdefault(k, [0.0, 0])
            a[0] += amt(t); a[1] += 1
    return [{"name": k, "amount": v[0], "count": v[1]} for k, v in sorted(m.items(), key=lambda kv: -kv[1][0])[:n]]


def why(rows, cat):
    ms = top_merchants(rows, cat)
    return ", ".join(f"{m['name']} ₹{round(m['amount']):,}" + (f" ({m['count']}x)" if m["count"] > 1 else "") for m in ms)


def fin_block(cur, prev, today):
    if cur is None:
        return {"ok": False}
    y, m = today.year, today.month
    days_in = calendar.monthrange(y, m)[1]
    py, pm = (y - 1, 12) if m == 1 else (y, m - 1)
    prev_days = calendar.monthrange(py, pm)[1]
    days = today.day
    oneoff = None
    if prev:
        ps = list(spends(prev)); ptot = sum(amt(t) for t in ps)
        big = max(ps, key=amt, default=None)
        if big is not None and ptot and amt(big) > 0.3 * ptot:
            oneoff = big
            prev = [t for t in prev if t is not big]
    ct = {k: v for k, v in cat_totals(cur).items() if k not in EXCL}
    pt = {k: v for k, v in cat_totals(prev or []).items() if k not in EXCL}
    spent, pspent = sum(ct.values()), sum(pt.values())
    avg, pavg = spent / days, (pspent / prev_days if prev else None)
    change = (avg - pavg) / pavg if pavg else None
    daily = {f"{y}-{m:02d}-{d:02d}": 0.0 for d in range(1, days_in + 1)}
    items = {}
    for t in spends(cur):
        d = ist_day(t["date"])
        if d in daily:
            daily[d] += amt(t)
            dm = items.setdefault(d, {})
            k = merchant(t)
            r = dm.setdefault(k, [0.0, k, cat_of(t), 0]); r[0] += amt(t); r[3] += 1
    fmt = lambda v: "₹" + f"{round(v):,}"
    ins = []
    if change is not None:
        if change <= 0:
            ins.append({"tone": "good", "text": f"You're spending {round(-change*100)}% less per day than last month ({fmt(avg)} vs {fmt(pavg)})."})
        else:
            ins.append({"tone": "bad", "text": f"You're spending {round(change*100)}% more per day than last month ({fmt(avg)} vs {fmt(pavg)})."})
    if oneoff is not None:
        ins.append({"tone": "info", "text": f"Last month's comparison leaves out one big payment of {fmt(amt(oneoff))} to {merchant(oneoff)} on {dt.date.fromisoformat(ist_day(oneoff['date'])).strftime('%d %b')} (tagged {cat_of(oneoff)}), so it doesn't distort the numbers."})
    deltas = [(c, v / days, pt.get(c, 0) / prev_days) for c, v in ct.items()] if prev else []
    ups = sorted([d for d in deltas if d[1] - d[2] > 50], key=lambda d: d[2] - d[1])
    if ups:
        c, n, w = ups[0]
        ins.append({"tone": "bad", "text": f"{c} is up to {fmt(n)}/day from {fmt(w)}/day. This month that's {why(cur, c)}."})
    downs = sorted([d for d in deltas if d[2] > 0 and d[1] - d[2] < -50], key=lambda d: d[1] - d[2])
    if downs:
        c, n, w = downs[0]
        lw = why(prev, c)
        ins.append({"tone": "good", "text": f"{c} is down to {fmt(n)}/day from {fmt(w)}/day." + (f" Last month it was mostly {lw}." if lw else "")})
    food = ct.get("Food & Drinks", 0)
    if spent and food / spent > 0.25:
        ins.append({"tone": "bad", "text": f"Food & Drinks is {round(food/spent*100)}% of your spending: {why(cur, 'Food & Drinks')}."})
    big = max(spends(cur), key=amt, default=None)
    if big is not None:
        ins.append({"tone": "info", "text": f"Biggest single spend: {fmt(amt(big))} at {merchant(big)} ({cat_of(big)}) on {dt.date.fromisoformat(ist_day(big['date'])).strftime('%d %b')}."})
    return {
        "ok": True,
        "month_label": today.strftime("%B %Y") + " so far",
        "avg_per_day": avg, "change": change,
        "total": spent,
        "cats": [{"category": k, "amount": v, "merchants": top_merchants(cur, k)} for k, v in sorted(ct.items(), key=lambda kv: -kv[1])],
        "daily": [{"day": k, "amount": v, "items": [{"amount": a, "merchant": mm + (f" ×{n}" if n > 1 else ""), "category": cc} for a, mm, cc, n in sorted(items.get(k, {}).values(), key=lambda r: -r[0])[:4]], "n": len(items.get(k, {}))} for k, v in daily.items()],
        "insights": ins[:6],
    }


def cards_block(cards, cur, today):
    lst = cards.get("credit_cards") if isinstance(cards, dict) else cards
    if not isinstance(lst, list):
        return []
    out = []
    for c in lst:
        if c.get("is_closed") or (c.get("relationship") or {}).get("role") == "CHILD":
            continue
        cc, pc = c.get("current_cycle") or {}, c.get("previous_cycle") or {}
        # A statement dated D includes spends made on D, so the new cycle starts the day after.
        # Fold's own amount_spent_this_cycle counts from D itself, which overstates the cycle.
        sd = (pc.get("statement_date") or "")[:10]
        start = (dt.date.fromisoformat(sd) + dt.timedelta(days=1)).isoformat() if sd else ""
        mine = [t for t in (cur or []) if t.get("account_id") == c["id"]]
        tx = [t for t in mine if (t.get("type") or "DEBIT").upper() == "DEBIT" and ist_day(t["date"]) >= (start or "0")]
        refunds = sum(amt(t) for t in mine if (t.get("type") or "").upper() == "CREDIT" and ist_day(t["date"]) >= (start or "0"))
        tx.sort(key=lambda t: t["date"], reverse=True)
        synced = (c.get("last_synced_at") or "")[:10]
        stale_days = (today - dt.date.fromisoformat(synced)).days if synced else None
        lim = float(cc.get("credit_limit") or pc.get("credit_limit") or 0)
        out.append({
            "name": (lambda i, n: n if n.lower().startswith(i.lower()) else f"{i} {n}".strip())(c.get('issuer_name') or '', (c.get('card_name') or '').title()), "last4": c.get("card_last_four"),
            "spent_cycle": (sum(amt(t) for t in tx) - refunds) if (start and tx) else float(cc.get("amount_spent_this_cycle") or 0),
            "cycle_start": start, "statement_date": (cc.get("statement_date") or "")[:10],
            "outstanding": float(c.get("outstanding") or 0), "limit": lim,
            "last_bill": float(pc.get("total_amount_due") or 0), "last_due": (pc.get("payment_due_date") or "")[:10],
            "last_paid_recorded": float(pc.get("amount_paid") or 0),
            "synced": synced, "stale_days": stale_days,
            "txns": [{"day": ist_day(t["date"]), "merchant": merchant(t), "category": cat_of(t), "amount": amt(t)} for t in tx[:6]],
            "n_txns": len(tx),
        })
    return out


def pf_block(hold, summ, mf, history, today_iso):
    hist = sorted([h for h in (history or []) if isinstance(h, dict) and h.get("date")], key=lambda h: h["date"])
    ok = isinstance(hold, dict) and isinstance(hold.get("data"), list) and isinstance(summ, dict) and "current_value" in summ
    mfl = mf if isinstance(mf, list) else (mf.get("data") if isinstance(mf, dict) else None)
    if ok:
        H = [{"tradingsymbol": h["tradingsymbol"], "quantity": float(h["quantity"]) + float(h.get("t1_quantity") or 0),
              "average_price": float(h["average_price"]), "last_price": float(h["last_price"]),
              "pnl": float(h["pnl"]), "day_change_percentage": float(h.get("day_change_percentage") or 0)} for h in hold["data"]]
        M = []
        for m in (mfl or []):
            v, i = float(m["quantity"]) * float(m["last_price"]), float(m["quantity"]) * float(m["average_price"])
            name = re.sub(r" - DIRECT PLAN.*$", "", m["fund"]).title()
            M.append({"fund": name, "value": v, "invested": i, "pnl": v - i, "pnl_pct": (v - i) / i if i else 0,
                      "units": float(m["quantity"]), "avg_nav": float(m["average_price"]), "nav": float(m["last_price"])})
        M.sort(key=lambda r: -r["value"])
        sv, si = float(summ["current_value"]), float(summ["invested_amount"])
        mv, mi = sum(r["value"] for r in M), sum(r["invested"] for r in M)
        snap = {"date": today_iso, "stocks_value": round(sv, 2), "stocks_invested": round(si, 2), "mf_value": round(mv, 2), "mf_invested": round(mi, 2)}
        hist = [h for h in hist if h["date"] != today_iso] + [snap]
        # allocation
        idx, gold = {"NIFTYBEES"}, {"GOLDCASE", "GOLDBEES"}
        b = {"Individual stocks": 0, "Active mutual funds": 0, "Index funds & ETFs": 0, "Gold": 0}
        for h in H:
            v = h["quantity"] * h["last_price"]
            b["Index funds & ETFs" if h["tradingsymbol"] in idx else "Gold" if h["tradingsymbol"] in gold else "Individual stocks"] += v
        for m in M:
            b["Index funds & ETFs" if re.search(r"INDEX|NIFTY 50", m["fund"], re.I) else "Active mutual funds"] += m["value"]
        t = sum(b.values()) or 1
        alloc = [{"bucket": k, "value": v, "share": v / t} for k, v in b.items()]
        # health facts
        rows = [(h["tradingsymbol"], h["quantity"] * h["last_price"], (h["last_price"] - h["average_price"]) / h["average_price"] if h["average_price"] else 0) for h in H]
        tot = sum(r[1] for r in rows) or 1
        health = []
        deep = sorted([r for r in rows if r[2] <= -0.25], key=lambda r: r[2])
        if deep:
            health.append({"tone": "bad", "text": f"{len(deep)} stocks are down 25% or more: {', '.join(r[0] for r in deep)}. Review whether your reason for owning each still holds."})
        tiny = [r for r in rows if r[1] < 0.01 * tot]
        if tiny:
            health.append({"tone": "info", "text": f"{len(tiny)} of {len(rows)} stock positions are each under 1% of your stock value. Positions that small barely move your returns but add tracking effort."})
        top5 = sorted(rows, key=lambda r: -r[1])[:5]
        health.append({"tone": "info", "text": f"Your top 5 stocks ({', '.join(r[0] for r in top5)}) are {round(sum(r[1] for r in top5)/tot*100)}% of your stock value."})
        ish = b["Index funds & ETFs"] / t
        health.append({"tone": "good" if ish >= 0.3 else "info", "text": f"{round(ish*100)}% of everything sits in low-cost index funds and ETFs."})
        value, invested = sv + mv, si + mi
        out = {"stale": False, "as_of": today_iso, "value": value, "invested": invested, "pnl": value - invested,
               "pnl_pct": (value - invested) / invested if invested else 0,
               "today_pnl": float(summ.get("today_pnl") or 0), "today_pct": float(summ.get("today_pnl_percent") or 0) / 100,
               "holdings": H, "mf": M, "alloc": alloc, "health": health}
    else:
        last = hist[-1] if hist else None
        value = (last["stocks_value"] + last["mf_value"]) if last else None
        invested = (last["stocks_invested"] + last["mf_invested"]) if last else None
        out = {"stale": True, "as_of": last["date"] if last else today_iso, "value": value, "invested": invested,
               "pnl": (value - invested) if last else None, "pnl_pct": ((value - invested) / invested) if last and invested else None,
               "holdings": [], "mf": [], "alloc": [], "health": []}
    out["history"] = [{"date": h["date"], "value": h["stocks_value"] + h["mf_value"], "invested": h["stocks_invested"] + h["mf_invested"]} for h in hist]
    out["snapshot"] = hist[-1] if (ok and hist) else None
    return out


def rows_of(obj):
    if isinstance(obj, dict) and isinstance(obj.get("rows"), list):
        return obj["rows"]
    return obj if isinstance(obj, list) else []


def cmd_init(a):
    key = AESGCM.generate_key(256)
    salt, wiv = secrets.token_bytes(16), secrets.token_bytes(12)
    it = 600000
    kek = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=it).derive(a.password.encode())
    wk = AESGCM(kek).encrypt(wiv, key, None)
    with open(os.path.join(HERE, "keywrap.json"), "w") as f:
        json.dump({"salt": b64(salt), "iter": it, "wiv": b64(wiv), "wk": b64(wk)}, f)
    print(key.hex())


def cmd_build(a):
    now = dt.datetime.now(IST)
    today = dt.date.fromisoformat(a.today) if a.today else now.date()
    raw = a.raw
    cur_t = txns(load(raw, "fold_cur.json"))
    fin = fin_block(cur_t, txns(load(raw, "fold_prev.json")), today)
    if fin.get("ok"):
        fin["cards"] = cards_block(load(raw, "fold_cards.json"), cur_t, today)
    pf = pf_block(load(raw, "kite_holdings.json"), load(raw, "kite_summary.json"), load(raw, "kite_mf.json"), load(raw, "history.json"), today.isoformat())
    snap = pf.pop("snapshot")
    brief = (rows_of(load(raw, "brief.json")) or [{}])[0]
    data = {"name": a.name, "today": today.isoformat(), "generated_label": now.strftime("%d %b %Y, %I:%M %p IST"),
            "fin": fin, "pf": pf, "brief": brief, "news": rows_of(load(raw, "news.json"))}
    with open(os.path.join(HERE, "keywrap.json")) as f:
        kw = json.load(f)
    iv = secrets.token_bytes(12)
    ct = AESGCM(bytes.fromhex(a.key)).encrypt(iv, json.dumps(data, ensure_ascii=False).encode(), None)
    payload = dict(kw, iv=b64(iv), ct=b64(ct))
    with open(os.path.join(HERE, "template.html")) as f:
        html = f.read()
    html = html.replace("/*__PAYLOAD__*/null", json.dumps(payload))
    with open(a.out, "w") as f:
        f.write(html)
    if snap and a.snapshot_out:
        with open(a.snapshot_out, "w") as f:
            json.dump(snap, f)
    print(json.dumps({"fin_ok": fin.get("ok"), "cards": len(fin.get("cards") or []), "pf_stale": pf["stale"], "holdings": len(pf["holdings"]), "brief_date": brief.get("date"), "news": len(data["news"]), "snapshot": snap}))


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    s = p.add_subparsers(dest="cmd", required=True)
    i = s.add_parser("init"); i.add_argument("--password", required=True)
    b = s.add_parser("build"); b.add_argument("--raw", required=True); b.add_argument("--key", required=True); b.add_argument("--out", required=True)
    b.add_argument("--name", default="Aman"); b.add_argument("--today"); b.add_argument("--snapshot-out")
    a = p.parse_args()
    cmd_init(a) if a.cmd == "init" else cmd_build(a)
