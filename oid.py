oid_info = {
    "1.3.6.1.4.1.2011.2.322.1.1.1.1": {"string": "告警编号"},
    "1.3.6.1.4.1.2011.2.322.1.1.1.2": {"string": "告警ID"},
    "1.3.6.1.4.1.2011.2.322.1.1.1.3": {"string": "告警名称"},
    "1.3.6.1.4.1.2011.2.322.1.1.1.4": {"string": "流水号"},
    "1.3.6.1.4.1.2011.2.322.1.1.1.5": {"string": "告警类型", "valtype":{"0":"故障告警", "1":"恢复告警", "4":"更新告警"}},
    "1.3.6.1.4.1.2011.2.322.1.1.1.6": {"string": "数据类型", "valtype":{"1":"紧急", "2":"重要", "3":"次要", "4":"提示"}},
    "1.3.6.1.4.1.2011.2.322.1.1.1.7": {"string": "告警产生时间"},
    "1.3.6.1.4.1.2011.2.322.1.1.1.8": {"string": "告警清除时间"},
    "1.3.6.1.4.1.2011.2.322.1.1.1.9": {"string": "清除类型", "valtype":{"-1":"未清除", "0":"自动清除", "2":"手工清除"}},
    "1.3.6.1.4.1.2011.2.322.1.1.1.10": {"string": "是否可以自动清除", "valtype":{"0":"是", "1":"否"}},
    "1.3.6.1.4.1.2011.2.322.1.1.1.11": {"string": "告警定位信息"},
    "1.3.6.1.4.1.2011.2.322.1.1.1.12": {"string": "告警额外信息"},
    "1.3.6.1.4.1.2011.2.322.1.1.1.13": {"string": "告警对象实例"},
    "1.3.6.1.4.1.2011.2.322.1.1.1.14": {"string": "告警MOC名称"}
    }

def get_oid_string(oid):
    if oid in oid_info:
        return oid_info[oid]["string"]

def get_val_string(oid, val):
    if oid in oid_info:
        item = oid_info[oid]
        if "valtype" in item:
            if val in item['valtype']:
                return item['valtype'][val]