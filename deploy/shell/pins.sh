# shellcheck shell=sh
# The pinned parts of the Ainkrad shell (N20). Each is a GitHub commit archive with its SHA-256; install-shell.sh refuses a
# download that does not match. To update one: change the commit, download
#   https://github.com/<repo>/archive/<commit>.tar.gz
# and put its `shasum -a 256` here. Nothing is fetched when a shell starts.
OMZ_REPO=ohmyzsh/ohmyzsh
OMZ_COMMIT=6010fb6260f359e71d99ba25f05f9215809b3ed2
OMZ_SHA256=c4fa7d0d075839768059ea44c35ca6513d69f1b64c744fbc259afa1d1dae2abd

P10K_REPO=romkatv/powerlevel10k
P10K_COMMIT=36f3045d69d1ba402db09d09eb12b42eebe0fa3b
P10K_SHA256=61a0ffd025d75457fa07f10805b12479522b6ab68c6733c816012377fc23e1ff

AUTOSUGGESTIONS_REPO=zsh-users/zsh-autosuggestions
AUTOSUGGESTIONS_COMMIT=85919cd1ffa7d2d5412f6d3fe437ebdbeeec4fc5
AUTOSUGGESTIONS_SHA256=20665e469e720e674964a66854d5534b9af78cdfd438512746ecd1ade8e819ce

SYNTAX_HIGHLIGHTING_REPO=zsh-users/zsh-syntax-highlighting
SYNTAX_HIGHLIGHTING_COMMIT=5eb677bb0fa9a3e60f0eff031dc13926e093df92
SYNTAX_HIGHLIGHTING_SHA256=c78570f573d6c87649da7e2921f4a2222e73f4b0951b3af7489c1897c5f1dac9

# powerlevel10k's own git status daemon, the release its gitstatus/install.info names (tarball SHA-256, per CPU).
GITSTATUSD_VERSION=v1.5.4
GITSTATUSD_SHA256_x86_64=9633816e7832109e530c9e2532b11a1edae08136d63aa7e40246c0339b7db304
GITSTATUSD_SHA256_aarch64=32b57eb28bf6d80b280e4020a0045184f8ca897b20b570c12948aa6838673225
