v

        ip = next((p.split("=")[1] for p in parts if p.startswith("ip=")), None)
        if not ip:
            return None

        event_type = "FAIL" if "LOGIN_FAIL" in line else "SUCCESS"
        return ts, ip, event_type

    except (ValueError, IndexError):
        return None
