#include <opencv2/opencv.hpp>
#include <opencv2/core.hpp>
#include <opencv2/imgproc.hpp>
#include <opencv2/highgui.hpp>
#include <random>
#include <iostream>
#include <string>
#include <map>
#include <cmath>

using namespace cv;
using namespace std;

class WatermarkSystem {
private:
    Size watermarkSize;
    double alpha;
    unsigned int key;
    mt19937 rng;

public:
    // ���캯��
    WatermarkSystem(Size size = Size(32, 32), double a = 0.05)
        : watermarkSize(size), alpha(a) {
        random_device rd;
        key = rd();
        rng.seed(key);
    }

    // ����ˮӡ
    Mat generateWatermark(const string& message = "") {
        Mat watermark(watermarkSize, CV_8UC1);

        if (!message.empty()) {
            // ������Ϣ����ˮӡ
            hash<string> hashFunc;
            size_t hashVal = hashFunc(message);
            rng.seed(hashVal);
        }
        else {
            // �������ˮӡ
            rng.seed(key);
        }

        uniform_int_distribution<int> dist(0, 1);
        for (int i = 0; i < watermark.rows; ++i) {
            for (int j = 0; j < watermark.cols; ++j) {
                watermark.at<uchar>(i, j) = dist(rng) * 255;
            }
        }

        return watermark;
    }

    // Ƕ��ˮӡ
    Mat embedWatermark(const string& imagePath, const Mat& watermark, const string& outputPath = "") {
        Mat image = imread(imagePath);
        if (image.empty()) {
            throw runtime_error("�޷���ȡͼ������·���Ƿ���ȷ");
        }

        // ת��ΪYCrCb��ɫ�ռ�
        Mat ycrcbImage;
        cvtColor(image, ycrcbImage, COLOR_BGR2YCrCb);

        // ����ͨ����ֻ��Yͨ��Ƕ��ˮӡ
        vector<Mat> channels;
        split(ycrcbImage, channels);
        Mat yChannel = channels[0].clone();
        yChannel.convertTo(yChannel, CV_32FC1);

        int h = yChannel.rows;
        int w = yChannel.cols;
        int wh = watermark.rows;
        int ww = watermark.cols;

        // ��ÿ��8x8�����DCT�任��Ƕ��ˮӡ
        for (int i = 0; i < h; i += 8) {
            for (int j = 0; j < w; j += 8) {
                // ȷ�����СΪ8x8
                if (i + 8 > h || j + 8 > w) continue;

                Mat block = yChannel(Rect(j, i, 8, 8));
                Mat dctBlock;

                // DCT�任
                dct(block, dctBlock);

                // Ƕ��ˮӡ
                int wi = (i / 8) % wh;
                int wj = (j / 8) % ww;
                uchar wmVal = watermark.at<uchar>(wi, wj);
                dctBlock.at<float>(5, 5) += alpha * (wmVal > 0 ? 1 : -1);

                // ��DCT�任
                idct(dctBlock, block);
            }
        }

        // �ϲ�ͨ����ת����BGR
        yChannel.convertTo(channels[0], CV_8UC1);
        merge(channels, ycrcbImage);
        Mat watermarkedImage;
        cvtColor(ycrcbImage, watermarkedImage, COLOR_YCrCb2BGR);

        // ����ͼ��
        if (!outputPath.empty()) {
            imwrite(outputPath, watermarkedImage);
        }

        return watermarkedImage;
    }

    // ��ȡˮӡ
    Mat extractWatermark(const string& originalImagePath, const Mat& watermarkedImage, double threshold = 0.0) {
        Mat originalImage = imread(originalImagePath);
        if (originalImage.empty()) {
            throw runtime_error("�޷���ȡԭʼͼ������·���Ƿ���ȷ");
        }

        // ת��ΪYCrCb��ɫ�ռ�
        Mat originalYCrCb, watermarkedYCrCb;
        cvtColor(originalImage, originalYCrCb, COLOR_BGR2YCrCb);
        cvtColor(watermarkedImage, watermarkedYCrCb, COLOR_BGR2YCrCb);

        // ��ȡYͨ��
        vector<Mat> originalChannels, watermarkedChannels;
        split(originalYCrCb, originalChannels);
        split(watermarkedYCrCb, watermarkedChannels);

        Mat originalY = originalChannels[0].clone();
        Mat watermarkedY = watermarkedChannels[0].clone();

        originalY.convertTo(originalY, CV_32FC1);
        watermarkedY.convertTo(watermarkedY, CV_32FC1);

        int h = originalY.rows;
        int w = originalY.cols;

        // ��ʼ����ȡ��ˮӡ
        Mat extractedWatermark(watermarkSize, CV_8UC1, Scalar(0));

        // ��ȡˮӡ
        for (int i = 0; i < h; i += 8) {
            for (int j = 0; j < w; j += 8) {
                // ȷ�����СΪ8x8
                if (i + 8 > h || j + 8 > w) continue;

                Mat originalBlock = originalY(Rect(j, i, 8, 8));
                Mat watermarkedBlock = watermarkedY(Rect(j, i, 8, 8));

                Mat originalDCT, watermarkedDCT;
                dct(originalBlock, originalDCT);
                dct(watermarkedBlock, watermarkedDCT);

                // �������
                double diff = watermarkedDCT.at<float>(5, 5) - originalDCT.at<float>(5, 5);

                // ȷ��ˮӡλ��
                int wi = (i / 8) % watermarkSize.height;
                int wj = (j / 8) % watermarkSize.width;

                // ��ֵ��
                extractedWatermark.at<uchar>(wi, wj) = (diff > threshold) ? 255 : 0;
            }
        }

        return extractedWatermark;
    }

    // ����ˮӡ���ƶ�
    double calculateSimilarity(const Mat& original, const Mat& extracted) {
        if (original.size() != extracted.size() || original.type() != extracted.type()) {
            throw invalid_argument("ˮӡ�ߴ�����Ͳ�ƥ��");
        }

        int total = original.total();
        int matches = 0;

        for (int i = 0; i < original.rows; ++i) {
            for (int j = 0; j < original.cols; ++j) {
                if (original.at<uchar>(i, j) == extracted.at<uchar>(i, j)) {
                    matches++;
                }
            }
        }

        return (static_cast<double>(matches) / total) * 100;
    }

    // ͼ������ - ����³���Բ���
    Mat flipImage(const Mat& image, int flipCode) {
        Mat result;
        flip(image, result, flipCode);
        return result;
    }

    Mat translateImage(const Mat& image, int x, int y) {
        Mat result;
        Mat translation = (Mat_<double>(2, 3) << 1, 0, x, 0, 1, y);
        warpAffine(image, result, translation, image.size());
        return result;
    }

    Mat cropImage(const Mat& image, int x1, int y1, int x2, int y2) {
        return image(Rect(x1, y1, x2 - x1, y2 - y1)).clone();
    }

    Mat adjustContrast(const Mat& image, double alpha, int beta = 0) {
        Mat result;
        image.convertTo(result, -1, alpha, beta);
        return result;
    }

    Mat addNoise(const Mat& image, double mean = 0, double var = 0.001) {
        Mat result, imageFloat;
        image.convertTo(imageFloat, CV_32FC3);
        imageFloat /= 255.0;

        Mat noise(image.size(), CV_32FC3);
        randn(noise, mean, sqrt(var));

        result = imageFloat + noise;
        result = min(result, 1.0);
        result = max(result, 0.0);
        result *= 255.0;
        result.convertTo(result, CV_8UC3);

        return result;
    }

    Mat rotateImage(const Mat& image, double angle) {
        Mat result;
        Point2f center(image.cols / 2.0f, image.rows / 2.0f);
        Mat rotation = getRotationMatrix2D(center, angle, 1.0);
        warpAffine(image, result, rotation, image.size());
        return result;
    }

    // ִ��³���Բ���
    map<string, double> performRobustnessTests(const string& originalImagePath,
        const Mat& watermarkedImage,
        const Mat& originalWatermark) {
        map<string, Mat> tests;

        // ��Ӹ��ֲ������
        tests["ԭʼͼ��"] = watermarkedImage;
        tests["ˮƽ��ת"] = flipImage(watermarkedImage, 1);
        tests["��ֱ��ת"] = flipImage(watermarkedImage, 0);
        tests["ƽ��(50,30)"] = translateImage(watermarkedImage, 50, 30);

        // �ü�10%�߿�
        int x1 = watermarkedImage.cols * 0.1;
        int y1 = watermarkedImage.rows * 0.1;
        int x2 = watermarkedImage.cols * 0.9;
        int y2 = watermarkedImage.rows * 0.9;
        tests["�ü�(10%,10%,90%,90%)"] = cropImage(watermarkedImage, x1, y1, x2, y2);

        tests["�߶Աȶ�(2.0)"] = adjustContrast(watermarkedImage, 2.0);
        tests["�ͶԱȶ�(0.5)"] = adjustContrast(watermarkedImage, 0.5);
        tests["��˹����"] = addNoise(watermarkedImage);
        tests["��ת(30��)"] = rotateImage(watermarkedImage, 30);

        map<string, double> results;

        // ����������ʾ���
        namedWindow("���Խ��", WINDOW_NORMAL);
        resizeWindow("���Խ��", 1200, 800);

        Mat display(800, 1200, CV_8UC3, Scalar(255, 255, 255));
        int y = 20;
        int x = 20;

        // ��ʾԭʼˮӡ
        putText(display, "ԭʼˮӡ", Point(x, y - 5), FONT_HERSHEY_SIMPLEX, 0.5, Scalar(0, 0, 0), 1);
        Mat resizedWatermark;
        resize(originalWatermark, resizedWatermark, Size(150, 150));
        cvtColor(resizedWatermark, resizedWatermark, COLOR_GRAY2BGR);
        resizedWatermark.copyTo(display(Rect(x, y, 150, 150)));
        x += 170;

        // ����ÿ���������
        int count = 0;
        for (auto& pair : tests) {
            try {
                // ��ȡˮӡ
                Mat extracted = extractWatermark(originalImagePath, pair.second);
                double similarity = calculateSimilarity(originalWatermark, extracted);
                results[pair.first] = similarity;

                // ��ʾ������ͼ��
                if (x + 150 > 1200) {
                    x = 20;
                    y += 170;
                }

                putText(display, pair.first, Point(x, y - 5), FONT_HERSHEY_SIMPLEX, 0.5, Scalar(0, 0, 0), 1);
                Mat resized;
                resize(pair.second, resized, Size(150, 150));
                resized.copyTo(display(Rect(x, y, 150, 150)));
                x += 170;

                // ��ʾ��ȡ��ˮӡ�����ƶ�
                putText(display, format("���ƶ�: %.2f%%", similarity), Point(x, y - 5),
                    FONT_HERSHEY_SIMPLEX, 0.5, Scalar(0, 0, 0), 1);
                Mat resizedExtracted;
                resize(extracted, resizedExtracted, Size(150, 150));
                cvtColor(resizedExtracted, resizedExtracted, COLOR_GRAY2BGR);
                resizedExtracted.copyTo(display(Rect(x, y, 150, 150)));
                x += 170;

                count++;
                if (count >= 4) break; // ������ʾ���������ⴰ�ڹ���
            }
            catch (const exception& e) {
                cerr << "���� " << pair.first << " ʧ��: " << e.what() << endl;
                results[pair.first] = -1;
            }
        }

        imshow("���Խ��", display);
        waitKey(0);

        return results;
    }
};

int main() {
    try {
        // ����ˮӡϵͳʵ��
        WatermarkSystem watermarkSystem(Size(32, 32), 0.08);

        // ����ˮӡ
        Mat watermark = watermarkSystem.generateWatermark("MySecretWatermark123");

        // Ƕ��ˮӡ
        string originalImagePath = "original_image.jpg"; // �滻Ϊ���ͼ��·��
        Mat watermarkedImage = watermarkSystem.embedWatermark(originalImagePath, watermark, "watermarked_image.jpg");
        cout << "ˮӡǶ��ɹ���" << endl;

        // ��ȡˮӡ���������ƶ�
        Mat extractedWatermark = watermarkSystem.extractWatermark(originalImagePath, watermarkedImage);
        double similarity = watermarkSystem.calculateSimilarity(watermark, extractedWatermark);
        cout << "ԭʼͼ��ˮӡ��ȡ���ƶ�: " << fixed << setprecision(2) << similarity << "%" << endl;

        // ��ʾԭʼˮӡ����ȡ��ˮӡ
        namedWindow("ˮӡ�Ա�", WINDOW_NORMAL);
        Mat watermarkDisplay(180, 340, CV_8UC3, Scalar(255, 255, 255));
        putText(watermarkDisplay, "ԭʼˮӡ", Point(10, 15), FONT_HERSHEY_SIMPLEX, 0.5, Scalar(0, 0, 0), 1);
        Mat resizedOrig, resizedExt;
        resize(watermark, resizedOrig, Size(150, 150));
        cvtColor(resizedOrig, resizedOrig, COLOR_GRAY2BGR);
        resizedOrig.copyTo(watermarkDisplay(Rect(10, 20, 150, 150)));

        putText(watermarkDisplay, format("��ȡ��ˮӡ (���ƶ�: %.2f%%)", similarity),
            Point(180, 15), FONT_HERSHEY_SIMPLEX, 0.5, Scalar(0, 0, 0), 1);
        resize(extractedWatermark, resizedExt, Size(150, 150));
        cvtColor(resizedExt, resizedExt, COLOR_GRAY2BGR);
        resizedExt.copyTo(watermarkDisplay(Rect(180, 20, 150, 150)));

        imshow("ˮӡ�Ա�", watermarkDisplay);
        waitKey(0);

        // ִ��³���Բ���
        cout << "\n��ʼ³���Բ���..." << endl;
        map<string, double> testResults = watermarkSystem.performRobustnessTests(
            originalImagePath, watermarkedImage, watermark);

        // ��ӡ���в��Խ��
        cout << "\n³���Բ��Խ��:" << endl;
        for (auto& pair : testResults) {
            if (pair.second == -1) {
                cout << pair.first << ": ʧ��" << endl;
            }
            else {
                cout << pair.first << ": " << fixed << setprecision(2) << pair.second << "%" << endl;
            }
        }

    }
    catch (const exception& e) {
        cerr << "��������: " << e.what() << endl;
        return 1;
    }

    return 0;
}
