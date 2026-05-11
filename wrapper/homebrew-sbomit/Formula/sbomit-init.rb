class SbomitInit < Formula
  desc "Add the SBOMit attestation pipeline to your project"
  homepage "https://sbomit.dev"
  url "https://github.com/sbomit/sbomit/releases/download/v0.1.0/sbomit-init-0.1.0.tar.gz"
  sha256 "PLACEHOLDER_SHA256"
  license "Apache-2.0"
  version "0.1.0"

  depends_on "gh"

  def install
    bin.install "install.sh" => "sbomit-init"
  end

  test do
    system "#{bin}/sbomit-init", "--help"
  end
end
