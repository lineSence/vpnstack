package tui

import (
	"fmt"
	"strings"

	"github.com/lineSence/vpnstack/internal/adopt"
	"github.com/lineSence/vpnstack/internal/core"
)

// Confirm — вопрос да/нет (по умолчанию «нет»).
func Confirm(q string) bool { return yes(q, false) }

var statusRU = map[string]string{
	"new": "новый", "imported": "импортирован", "migrated": "перенесён",
	"rolled_back": "откачен", "cleaned": "перенесён", "conflict": "конфликт",
}

// AdoptReport печатает итог сканирования.
func AdoptReport(r *adopt.Report) {
	head("Найденные установки без vpnstack")
	if len(r.Found) == 0 {
		fmt.Println("Не найдено.")
	}
	for _, f := range r.Found {
		st := statusRU[f.Status]
		if st == "" {
			st = f.Status
		}
		fmt.Printf(cB+"%-10s"+cN+" %s [%s]\n", f.ID, f.Title, st)
		fmt.Printf("    источник: %s\n", f.Origin.Source)
		if len(f.Origin.Ports) > 0 {
			fmt.Printf("    порты: %s\n", strings.Join(f.Origin.Ports, ", "))
		}
		if len(f.UserNames) > 0 {
			names := f.UserNames
			more := ""
			if len(names) > 8 {
				names, more = names[:8], fmt.Sprintf(" … ещё %d", len(f.UserNames)-8)
			}
			fmt.Printf("    пользователи (%d): %s%s\n", len(f.UserNames), strings.Join(names, ", "), more)
		}
		for _, w := range f.Warnings {
			fmt.Printf("    "+cY+"[!]"+cN+" %s\n", w)
		}
		for _, w := range f.Risky {
			fmt.Printf("    "+cY+"[нужен --force]"+cN+" %s\n", w)
		}
		for _, w := range f.Blocking {
			fmt.Printf("    "+cR+"[x]"+cN+" %s\n", w)
		}
		if f.Status == "conflict" {
			fmt.Printf("    " + cR + "[x]" + cN + " этот сервис уже установлен vpnstack\n")
		}
	}
	if len(r.Foreign) > 0 {
		head("Посторонние программы на нужных портах")
		for _, x := range r.Foreign {
			fmt.Printf("  %s/%d — %s (pid %d %s)\n      %s\n", x.Proto, x.Port, x.Process, x.PID, x.Unit, x.Hint)
		}
	}
	for _, n := range r.Notes {
		fmt.Println("  " + n)
	}
}

// adoptMenu — перенос существующих сервисов: сканирование → импорт → перенос.
func adoptMenu(e *core.Engine) {
	r := e.AdoptScan()
	AdoptReport(r)
	var ready []string
	for _, f := range r.Found {
		if f.Status == "new" || f.Status == "imported" || f.Status == "rolled_back" {
			if len(f.Blocking) == 0 {
				ready = append(ready, f.ID)
			}
		}
	}
	if len(ready) == 0 {
		if len(e.Adopted()) > 0 {
			adoptAfter(e)
		}
		return
	}
	ids := strings.Fields(ask("Какие перенести (через пробел, all — все)", strings.Join(ready, " ")))
	if len(ids) == 0 {
		return
	}
	force := false
	for _, f := range r.Found {
		if len(f.Risky) > 0 && (ids[0] == "all" || containsS(ids, f.ID)) {
			force = yes(fmt.Sprintf("%s: есть предупреждения (см. выше). Всё равно переносить?", f.Title), false)
			if !force {
				return
			}
		}
	}
	msgs, err := e.AdoptImport(ids, force)
	for _, m := range msgs {
		info("%s", m)
	}
	if err != nil {
		bad("%v", err)
		return
	}
	fmt.Println()
	fmt.Println(e.MigrateSummary(ids))
	if !yes("Переключить сейчас?", true) {
		info("Импорт сохранён; перенести позже: vpnstack adopt migrate")
		return
	}
	if err := e.AdoptMigrate(ids, core.MigrateOpts{Force: force}); err != nil {
		bad("%v", err)
		return
	}
	info("Перенос завершён. Проверьте подключение клиентов.")
}

func adoptAfter(e *core.Engine) {
	fmt.Println(" 1) Откатить перенос (вернуть старые установки)\n 2) Удалить старые остановленные установки\n 0) Назад")
	switch ask("Выбор", "0") {
	case "1":
		if err := e.AdoptRollback(nil); err != nil {
			bad("%v", err)
		}
	case "2":
		if yes("После удаления откат невозможен. Удалить?", false) {
			if err := e.AdoptCleanup(nil); err != nil {
				bad("%v", err)
			}
		}
	}
}

func containsS(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}
