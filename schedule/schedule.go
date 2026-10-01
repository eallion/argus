package schedule

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// ParseDuration parses natural language durations like "12h", "1d", "30m", "2d", "1w"
func ParseDuration(raw string) (time.Duration, bool) {
	s := strings.TrimSpace(strings.ToLower(raw))
	if s == "" {
		return 0, false
	}

	// 匹配带有天 (d) 或周 (w) 后缀的自然语言表达
	dayRegex := regexp.MustCompile(`^(\d+)\s*d$`)
	if m := dayRegex.FindStringSubmatch(s); len(m) == 2 {
		days, err := strconv.Atoi(m[1])
		if err == nil && days > 0 {
			return time.Duration(days) * 24 * time.Hour, true
		}
	}

	weekRegex := regexp.MustCompile(`^(\d+)\s*w$`)
	if m := weekRegex.FindStringSubmatch(s); len(m) == 2 {
		weeks, err := strconv.Atoi(m[1])
		if err == nil && weeks > 0 {
			return time.Duration(weeks) * 7 * 24 * time.Hour, true
		}
	}

	// 尝试标准 Go duration 解析，例如 12h, 30m, 1h30m
	if d, err := time.ParseDuration(s); err == nil && d > 0 {
		return d, true
	}

	return 0, false
}

// CronField represents allowed integer values for a cron field
type CronField map[int]bool

// CronSchedule represents parsed 5-field cron
type CronSchedule struct {
	Minutes  CronField
	Hours    CronField
	Days     CronField
	Months   CronField
	Weekdays CronField
}

// ParseCron parses standard 5-part cron: "minute hour day month weekday"
func ParseCron(expr string) (*CronSchedule, error) {
	parts := strings.Fields(strings.TrimSpace(expr))
	if len(parts) != 5 {
		return nil, fmt.Errorf("Cron 表达式需包含 5 个字段 (分 时 日 月 周)，当前为 %d 个", len(parts))
	}

	mins, err := parseCronField(parts[0], 0, 59)
	if err != nil {
		return nil, fmt.Errorf("分钟字段解析错误 (%s): %w", parts[0], err)
	}

	hours, err := parseCronField(parts[1], 0, 23)
	if err != nil {
		return nil, fmt.Errorf("小时字段解析错误 (%s): %w", parts[1], err)
	}

	days, err := parseCronField(parts[2], 1, 31)
	if err != nil {
		return nil, fmt.Errorf("日期字段解析错误 (%s): %w", parts[2], err)
	}

	months, err := parseCronField(parts[3], 1, 12)
	if err != nil {
		return nil, fmt.Errorf("月份字段解析错误 (%s): %w", parts[3], err)
	}

	weekdays, err := parseCronField(parts[4], 0, 7)
	if err != nil {
		return nil, fmt.Errorf("星期字段解析错误 (%s): %w", parts[4], err)
	}
	// 星期 7 转换为 0 (周日)
	if weekdays[7] {
		weekdays[0] = true
		delete(weekdays, 7)
	}

	return &CronSchedule{
		Minutes:  mins,
		Hours:    hours,
		Days:     days,
		Months:   months,
		Weekdays: weekdays,
	}, nil
}

func parseCronField(field string, min, max int) (CronField, error) {
	res := make(CronField)
	items := strings.Split(field, ",")
	for _, item := range items {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}

		step := 1
		rangeStr := item
		if strings.Contains(item, "/") {
			parts := strings.Split(item, "/")
			if len(parts) != 2 {
				return nil, fmt.Errorf("无效的步长格式: %s", item)
			}
			rangeStr = parts[0]
			s, err := strconv.Atoi(parts[1])
			if err != nil || s <= 0 {
				return nil, fmt.Errorf("无效的步长数值: %s", parts[1])
			}
			step = s
		}

		var start, end int
		if rangeStr == "*" {
			start = min
			end = max
		} else if strings.Contains(rangeStr, "-") {
			parts := strings.Split(rangeStr, "-")
			if len(parts) != 2 {
				return nil, fmt.Errorf("无效的区间格式: %s", rangeStr)
			}
			s, err1 := strconv.Atoi(parts[0])
			e, err2 := strconv.Atoi(parts[1])
			if err1 != nil || err2 != nil || s > e {
				return nil, fmt.Errorf("无效的区间取值: %s", rangeStr)
			}
			start = s
			end = e
		} else {
			val, err := strconv.Atoi(rangeStr)
			if err != nil {
				return nil, fmt.Errorf("无效的数值: %s", rangeStr)
			}
			if step > 1 {
				start = val
				end = max
			} else {
				start = val
				end = val
			}
		}

		if start < min || end > max {
			return nil, fmt.Errorf("数值超出允许范围 [%d, %d]: %s", min, max, item)
		}

		for v := start; v <= end; v += step {
			res[v] = true
		}
	}

	if len(res) == 0 {
		return nil, fmt.Errorf("字段为空: %s", field)
	}

	return res, nil
}

// Next finds the next execution time strictly after the given reference time
func (c *CronSchedule) Next(ref time.Time) time.Time {
	// 从下整分钟开始寻找
	t := ref.Truncate(time.Minute).Add(time.Minute)

	// 最多搜索 5 年（约 260 万分钟）
	limit := t.Add(5 * 365 * 24 * time.Hour)

	for t.Before(limit) {
		month := int(t.Month())
		if !c.Months[month] {
			// 跳到下个月初
			t = time.Date(t.Year(), t.Month()+1, 1, 0, 0, 0, 0, t.Location())
			continue
		}

		day := t.Day()
		weekday := int(t.Weekday())
		if !c.Days[day] || !c.Weekdays[weekday] {
			// 跳到明天
			t = time.Date(t.Year(), t.Month(), t.Day()+1, 0, 0, 0, 0, t.Location())
			continue
		}

		hour := t.Hour()
		if !c.Hours[hour] {
			// 跳到下个小时
			t = time.Date(t.Year(), t.Month(), t.Day(), t.Hour()+1, 0, 0, 0, t.Location())
			continue
		}

		minute := t.Minute()
		if !c.Minutes[minute] {
			t = t.Add(time.Minute)
			continue
		}

		return t
	}

	return time.Time{}
}

// ValidateSpec validates whether spec is a valid natural language duration or cron expression
func ValidateSpec(spec string) error {
	trimmed := strings.TrimSpace(spec)
	if trimmed == "" {
		return nil
	}

	// 1. 尝试作为自然语言 duration
	if d, ok := ParseDuration(trimmed); ok {
		if d < 1*time.Minute {
			return fmt.Errorf("检测周期不得低于 1 分钟")
		}
		return nil
	}

	// 2. 尝试作为 cron
	if _, err := ParseCron(trimmed); err == nil {
		return nil
	}

	return fmt.Errorf("不支持的巡检计划格式 %q (支持如 12h, 1d, 30m 或 Cron 表达式如 0 */6 * * *)", spec)
}

// NextExecutionTime calculates the next execution time based on spec and reference time
func NextExecutionTime(spec string, after time.Time) (time.Time, error) {
	trimmed := strings.TrimSpace(spec)
	if trimmed == "" {
		return time.Time{}, nil
	}

	// 1. 自然语言周期
	if d, ok := ParseDuration(trimmed); ok {
		if d < 1*time.Minute {
			d = 1 * time.Minute
		}
		return after.Add(d), nil
	}

	// 2. Cron 表达式
	cron, err := ParseCron(trimmed)
	if err != nil {
		return time.Time{}, err
	}

	next := cron.Next(after)
	if next.IsZero() {
		return time.Time{}, fmt.Errorf("无法计算下一次 Cron 触发时间")
	}
	return next, nil
}
