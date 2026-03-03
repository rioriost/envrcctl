class Envrcctl < Formula
  include Language::Python::Virtualenv

  desc "Secure, structured management of .envrc files"
  homepage "https://github.com/rioriost/homebrew-envrcctl"
  url "REPLACE_WITH_RELEASE_TARBALL_URL"
  sha256 "REPLACE_WITH_SHA256"
  license "MIT"

  depends_on "python@3.14"

  resource "typer" do
    url "REPLACE_WITH_TYPER_URL"
    sha256 "REPLACE_WITH_TYPER_SHA256"
  end

  def install
    virtualenv_install_with_resources
  end

  test do
    system "#{bin}/envrcctl", "--help"
  end
end
