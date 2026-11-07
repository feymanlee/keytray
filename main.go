// keytray is a menu-bar authenticator: a tray icon opens a flyout panel
// with TOTP/HOTP codes, encrypted at rest with a master password.
package main

import (
	"embed"
	"log"
	"os"
	"path/filepath"

	"github.com/egoist/mygo"
)

//go:embed resources/icon.png
//go:embed resources/tray-template.png
//go:embed all:resources/icons
var resources embed.FS

// iconPNG is the full-color app icon used as the default tray icon on
// platforms without template-image support.
var iconPNG = mustRead("resources/icon.png")

// trayTemplatePNG is the monochrome menu-bar icon used by macOS.
var trayTemplatePNG = mustRead("resources/tray-template.png")

func mustRead(name string) []byte {
	b, err := resources.ReadFile(name)
	if err != nil {
		panic(err)
	}
	return b
}

// migrateDataDir moves data written under the old lowercase app name
// ("keytray") into the renamed data directory, once: only when the old
// vault exists and the new one does not yet.
func migrateDataDir(newDir string) {
	oldDir := filepath.Join(filepath.Dir(newDir), "keytray")
	if oldDir == newDir {
		return
	}
	for _, name := range []string{"vault.kt", "settings.json"} {
		old := filepath.Join(oldDir, name)
		new := filepath.Join(newDir, name)
		if fileExists(old) && !fileExists(new) {
			if err := os.MkdirAll(newDir, 0o700); err != nil {
				log.Printf("migrate data dir: %v", err)
				return
			}
			if err := os.Rename(old, new); err != nil {
				log.Printf("migrate %s: %v", name, err)
			}
		}
	}
}

func main() {
	if !mygo.App.RequestSingleInstanceLock() {
		return // the running instance opens its panel (OnSecondInstance)
	}
	mygo.App.SetName("Keytray") // before App.Path: the name picks the data dir

	dir, err := mygo.App.Path(mygo.PathUserData)
	if err != nil {
		log.Fatal("user data dir: ", err)
	}
	migrateDataDir(dir) // pre-rename data (lowercase "keytray") → new name

	a := &app{state: newPanelState(filepath.Join(dir, "vault.kt"), filepath.Join(dir, "settings.json"))}
	mygo.App.SetActivationPolicy(mygo.ActivationPolicyAccessory) // no Dock icon
	mygo.App.OnWindowAllClosed(func() {})                        // keep running
	mygo.App.OnSecondInstance(func([]string, string) { a.toggle() })
	mygo.App.WhenReady(a.ready)
	if err := mygo.App.Run(); err != nil {
		log.Fatal(err)
	}
}
