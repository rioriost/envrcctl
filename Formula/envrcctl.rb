class Envrcctl < Formula
  include Language::Python::Virtualenv

  desc "Secure, structured management of .envrc files"
  homepage "https://github.com/rioriost/homebrew-envrcctl"
  url "REPLACE_WITH_RELEASE_TARBALL_URL"
  sha256 "REPLACE_WITH_SHA256"
  license "MIT"

  depends_on "python@3.14"

  resource "typer" do
    url "https://files.pythonhosted.org/packages/f5/24/cb09efec5cc954f7f9b930bf8279447d24618bb6758d4f6adf2574c41780/typer-0.24.1.tar.gz"
    sha256 "e39b4732d65fbdcde189ae76cf7cd48aeae72919dea1fdfc16593be016256b45"
  end

  def install
    virtualenv_install_with_resources
  end

  test do
    system "#{bin}/envrcctl", "--help"
  end
end
